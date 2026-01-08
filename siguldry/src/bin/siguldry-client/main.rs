// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use siguldry::{
    client::{Client, Config},
    config::load_config,
};
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan, layer::SubscriberExt};

// The path, relative to $XDG_CONFIG_HOME, of the default config file location.
const DEFAULT_CONFIG: &str = "siguldry/client.toml";

mod proxy;

/// The siguldry client
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// The path to the client's configuration file.
    ///
    /// If no path is provided, the configuration file at $XDG_CONFIG_HOME/siguldry/client.toml
    /// is used, if it exists. If it does not exist, the configuration defaults are used. Note
    /// that the defaults include server hostnames and are useful only as an example.
    ///
    /// To view the client configuration, run the `config` subcommand.
    #[arg(long, short, env = "SIGULDRY_CLIENT_CONFIG")]
    config: Option<PathBuf>,

    /// The directory containing the client's authentication secrets.
    ///
    /// Any file referenced in the configuration that are not absolute paths are
    /// expected to be in this directory. If this value is not supplied and any
    /// configuration values are relative paths, the client will exit with an error.
    ///
    /// The recommended approach to securely store your credentials is with systemd-creds.
    ///
    /// # Example
    ///
    /// ```bash
    /// # Requires systemd v258
    ///
    /// # Encrypt the necessary credentials
    /// $ systemd-creds encrypt /secure/ramfs/siguldry.client.private_key.pem \
    ///     "$HOME/.config/credstore.encrypted/siguldry.client.private_key.pem"
    /// $ systemd-creds encrypt /secure/ramfs/siguldry.client.certificate.pem \
    ///     "$HOME/.config/credstore.encrypted/siguldry.client.certificate.pem"
    /// $ systemd-creds encrypt /secure/ramfs/siguldry.ca_certificate.pem \
    ///     "$HOME/.config/credstore.encrypted/siguldry.ca_certificate.pem"
    ///
    /// # Spawn a shell where systemd decrypts the credentials for you.
    /// $ systemd-run --user -S -p "ImportCredentials=siguldry.*"
    /// $ siguldry-client whoami
    /// ```
    #[arg(long, env = "CREDENTIALS_DIRECTORY", verbatim_doc_comment)]
    credentials_directory: Option<PathBuf>,

    /// A set of one or more comma-separated directives to filter logs.
    ///
    /// The general format is "target_name[span_name{field=value}]=level" where level is
    /// one of TRACE, DEBUG, INFO, WARN, ERROR.
    ///
    /// Details: https://docs.rs/tracing-subscriber/0.3.19/tracing_subscriber/filter/struct.EnvFilter.html#directives
    #[arg(
        long,
        env = "SIGULDRY_CLIENT_LOG",
        default_value = "WARN,siguldry=INFO"
    )]
    pub log_filter: String,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Attempt to authenticate with the server and print the username of the authenticated user.
    Whoami,
    /// List the users on the server.
    ListUsers,
    /// See the current configuration, or the defaults if no configuration file is supplied.
    Config,

    /// Run the client as a service that listens on a Unix socket for signing requests to proxy.
    ///
    /// In this mode, any process with access to the socket can sign content. This is primarily
    /// useful as a way to keep secrets out of processes handling content.
    Proxy {
        /// The location of the varlink Unix socket
        socket: PathBuf,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let opts = Cli::parse();

    // Unfortunately we can't use clap's value_parser since EnvFilter does not
    // implement Clone.
    let log_filter = EnvFilter::builder().parse(&opts.log_filter).context(
        "SIGULDRY_CLIENT_LOG contains an invalid log directive; refer to \
            https://docs.rs/tracing-subscriber/0.3.19/tracing_subscriber/\
            filter/struct.EnvFilter.html#directives for format details.",
    )?;
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_writer(std::io::stderr);
    let registry = tracing_subscriber::registry()
        .with(stderr_layer)
        .with(log_filter);
    tracing::subscriber::set_global_default(registry)
        .expect("Programming error: set_global_default should only be called once.");

    let mut config = load_config::<Config>(opts.config, PathBuf::from(DEFAULT_CONFIG).as_path())?;

    if let Command::Config = opts.command {
        println!(
            "# This is the current configuration\n\n{config}\n# This concludes the configuration.\n"
        );

        opts.credentials_directory
        .as_ref()
        .map(|path| config.credentials.with_credentials_dir(path).inspect_err(|error|{
            eprintln!("The configuration format is valid, but the referenced credentials aren't valid: {error:?}");
        }));
        return Ok(());
    }

    opts.credentials_directory
        .as_ref()
        .map(|path| config.credentials.with_credentials_dir(path));
    let client = Client::new(config)?;
    match opts.command {
        Command::Whoami => {
            let user = client.who_am_i().await?;
            println!("Hello, {user}, you can successfully authenticate with the server!");
        }
        Command::ListUsers => {
            let users = client.list_users().await?;
            let users = users.join("\n");
            println!("{users}");
        }
        Command::Config => unreachable!("Command handled prior to this match"),
        Command::Proxy { socket } => {
            let halt_token = CancellationToken::new();
            tokio::spawn(signal_handler(halt_token.clone()));
            proxy::listen(client, socket, halt_token)?.await??;
        }
    }

    Ok(())
}

/// Install and manage signal handlers for the process.
///
/// # SIGTERM and SIGINT
///
/// Sending SIGTERM or SIGINT to the process will cause it to stop accepting new
/// signing requests. Existing signing requests will be allowed to complete
/// before the process shuts down.
async fn signal_handler(halt_token: CancellationToken) -> Result<(), anyhow::Error> {
    let mut sigterm_stream = signal(SignalKind::terminate()).inspect_err(|error| {
        tracing::error!(?error, "Failed to register a SIGTERM signal handler");
    })?;
    let mut sigint_stream = signal(SignalKind::interrupt()).inspect_err(|error| {
        tracing::error!(?error, "Failed to register a SIGINT signal handler");
    })?;

    loop {
        tokio::select! {
            _ = sigterm_stream.recv() => {
                tracing::info!("SIGTERM received, beginning service shutdown");
                halt_token.cancel();
            }
            _ = sigint_stream.recv() => {
                tracing::info!("SIGINT received, beginning service shutdown");
                halt_token.cancel();
            }
        }
    }
}
