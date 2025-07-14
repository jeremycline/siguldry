// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::{path::PathBuf, time::Duration};

use anyhow::Context;
use clap::Parser;
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, EnvFilter};

#[derive(Debug, Parser)]
struct Cli {
    /// The bridge's hostname used to connect to it as well as validate its TLS certificate.
    #[arg(long)]
    bridge_hostname: String,
    /// The port to use when connecting to the bridge.
    #[arg(long)]
    bridge_port: u16,
    /// The server's hostname, used to validate its TLS certificate.
    #[arg(long)]
    server_hostname: String,
    /// The username to authenticate as.
    #[arg(long)]
    user_name: String,
    /// The client certificate used to authenticate the user.
    #[arg(long)]
    certificate: PathBuf,
    /// The private key for the client certificate.
    #[arg(long)]
    private_key: PathBuf,
    /// The path to a file containing the passphrase protecting the private key, if
    /// the key is encrypted.
    #[arg(long)]
    private_key_passphrase: Option<PathBuf>,
    /// Path to the certificate authority's PEM-encoded certificate, used to validate
    /// the Sigul bridge's and Sigul server's TLS certificate.
    #[arg(long)]
    ca_file: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    ListUsers {
        #[arg(long)]
        admin_passphrase: PathBuf,
    },
    /// Show information about a user.
    ///
    /// The only information available is whether or not the user is an administrator.
    UserInfo {
        #[arg(long)]
        admin_passphrase: PathBuf,
        /// The name of the user to look up.
        #[arg(long)]
        name: String,
    },
    SignPe {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        key_passphrase: PathBuf,
        #[arg(long)]
        key_name: String,
        #[arg(long)]
        cert_name: String,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let opts = Cli::parse();

    let default_directive = "WARN"
        .parse()
        .expect("Programming error: default directive should be valid");
    let log_filter = EnvFilter::builder()
        .with_default_directive(default_directive)
        .with_env_var("SIGULDRY_LOG")
        .from_env()?;
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_writer(std::io::stderr);
    let registry = tracing_subscriber::registry()
        .with(stderr_layer)
        .with(log_filter);
    tracing::subscriber::set_global_default(registry)
        .expect("Programming error: set_global_default should only be called once.");

    let tls_config = siguldry::client::TlsConfig::new(
        opts.certificate,
        opts.private_key,
        opts.private_key_passphrase,
        opts.ca_file,
    )?;
    let client = siguldry::client::Client::new(
        tls_config,
        opts.bridge_hostname,
        opts.bridge_port,
        opts.server_hostname,
        opts.user_name.clone(),
    );
    match opts.command {
        Command::ListUsers { admin_passphrase } => {
            let users = tokio::time::timeout(
                Duration::from_secs(30),
                client.users(admin_passphrase.as_path().try_into()?),
            )
            .await
            .context("request timed out")??;
            for user in users {
                println!("{user}");
            }
        }
        Command::UserInfo {
            admin_passphrase,
            name,
        } => {
            let user = tokio::time::timeout(
                Duration::from_secs(30),
                client.get_user(admin_passphrase.as_path().try_into()?, name),
            )
            .await
            .context("request timed out")??;
            println!("Administrator: {}", if user.admin() { "yes" } else { "no" });
        }
        Command::SignPe {
            input,
            output,
            key_passphrase,
            key_name,
            cert_name,
        } => {
            let input = tokio::fs::File::open(&input)
                .await
                .with_context(|| format!("failed to read input file '{}'", &input.display()))?;
            let signed_output = tokio::fs::File::create_new(&output)
                .await
                .with_context(|| format!("failed to create output file '{}'", &output.display()))?;

            tokio::time::timeout(Duration::from_secs(60), async {
                client
                    .sign_pe(
                        input,
                        signed_output,
                        key_passphrase.as_path().try_into()?,
                        key_name,
                        cert_name,
                    )
                    .await
                    .inspect_err(|_| {
                        let _ = std::fs::remove_file(&output);
                    })
            })
            .await
            .context("request timed out")??;
        }
    }

    Ok(())
}
