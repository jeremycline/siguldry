// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use lapin::{
    Connection, ConnectionProperties,
    options::{BasicConsumeOptions, QueueBindOptions, QueueDeclareOptions},
    tcp::OwnedTLSConfig,
    types::{FieldTable, LongString},
};
use siguldry::client;
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{Instrument, instrument};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan, layer::SubscriberExt};

use futures_lite::stream::StreamExt;

// The name of the default config file location. Since this is expected to run under systemd,
// this is looked for under the provided CONFIGURATION_DIRECTORY environment variable.
const DEFAULT_CONFIG: &str = "autosign.toml";

#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// The path to the autosign configuration file.
    ///
    /// If no path is provided, the defaults are used. To view the service configuration,
    /// run the `config` subcommand.
    #[arg(long, short, env = "SIGULDRY_AUTOSIGN_CONFIG")]
    config: Option<PathBuf>,

    /// A set of one or more comma-separated directives to filter logs.
    ///
    /// The general format is "target_name[span_name{field=value}]=level" where level is
    /// one of TRACE, DEBUG, INFO, WARN, ERROR.
    ///
    /// Details: https://docs.rs/tracing-subscriber/0.3.19/tracing_subscriber/filter/struct.EnvFilter.html#directives
    #[arg(
        long,
        env = "SIGULDRY_AUTOSIGN_LOG",
        default_value = "WARN,siguldry=INFO,siguldry_autosign=INFO,lapin=DEBUG"
    )]
    pub log_filter: String,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Run the service.
    Listen {},

    /// See the current configuration.
    Config {},
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Cli::parse();

    // Unfortunately we can't use clap's value_parser since EnvFilter does not
    // implement Clone.
    let log_filter = EnvFilter::builder().parse(&opts.log_filter).context(
        "SIGULDRY_BRIDGE_LOG contains an invalid log directive; refer to \
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

    match opts.command {
        Command::Listen {} => {
            let halt_token = CancellationToken::new();
            tokio::spawn(signal_handler(halt_token.clone()));
            autosign(halt_token).await?;
        }
        Command::Config {} => {
            let config = "huh";
            println!(
                "# This is the current configuration\n\n{config}\n# This concludes the configuration.\n"
            );
        }
    }

    Ok(())
}

#[instrument]
async fn autosign(halt_token: CancellationToken) -> anyhow::Result<()> {
    let addr =
        "amqps://fedora:@rabbitmq.fedoraproject.org/%2Fpublic_pubsub?auth_mechanism=external"
            .into();
    let mut properties = ConnectionProperties::default();
    properties
        .client_properties
        .insert("app".into(), LongString::from("Siguldry Autosign").into());

    let ca_cert_pem = std::fs::read_to_string("/etc/fedora-messaging/cacert.pem")?;
    let client_cert_pem = std::fs::read_to_string("/etc/fedora-messaging/fedora-cert.pem")?
        .as_bytes()
        .to_vec();
    let client_key_pem = std::fs::read_to_string("/etc/fedora-messaging/fedora-key.pem")?
        .as_bytes()
        .to_vec();
    let auth = OwnedTLSConfig {
        cert_chain: Some(ca_cert_pem),
        identity: Some(lapin::tcp::OwnedIdentity::PKCS8 {
            pem: client_cert_pem,
            key: client_key_pem,
        }),
    };

    let conn = Connection::connect_with_config(addr, properties, auth).await?;
    tracing::info!(?addr, "Successfully connected");

    let channel = conn.create_channel().await?;
    let queue_options = QueueDeclareOptions {
        passive: false,
        durable: false,
        exclusive: true,
        auto_delete: true,
        nowait: false,
    };
    let queue_arguments = FieldTable::default();
    let queue = channel
        .queue_declare("", queue_options, queue_arguments)
        .await?;
    tracing::info!("Declared queue {}", queue.name().as_str());
    let bind_opts = QueueBindOptions { nowait: false };
    let routing_keys = [
        "org.fedoraproject.*.pungi.compose.ostree",
        "org.fedoraproject.*.coreos.build.request.artifacts-sign",
        "org.fedoraproject.*.coreos.build.request.ostree-sign",
        "org.fedoraproject.*.robosignatory.xml-sign",
        "org.fedoraproject.*.buildsys.tag",
    ];
    for routing_key in routing_keys {
        channel
            .queue_bind(
                queue.name().as_str(),
                "amq.topic",
                routing_key,
                bind_opts,
                FieldTable::default(),
            )
            .await?;
        tracing::info!("Bound queue {} to {}", queue.name().as_str(), routing_key);
    }

    let mut consumer = channel
        .basic_consume(
            queue.name().as_str(),
            "my-consumer-tag",
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await?;
    loop {
        tokio::select! {
            _ = halt_token.cancelled() => {
                tracing::info!("Shutdown requested, no new requests will be accepted");
                let _ = conn.close(0, "".into()).await;
                break;
            }
            message = consumer.next() => {
                match message {
                    Some(Ok(message)) => {
                        let payload = String::from_utf8(message.data)?;
                        println!("payload: {payload}")
                    }
                    Some(Err(e)) => println!("Error: {e:?}"),
                    None => break,
                }
            }
        }
    }

    // TODO probably want a joinset
    let request_tracker = TaskTracker::new();

    Ok(())
}
