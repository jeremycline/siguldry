// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use anyhow::Context;
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, EnvFilter};

mod cli;
mod config;
mod service;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), anyhow::Error> {
    let opts = cli::Cli::parse();

    let log_filter = EnvFilter::builder()
        .with_env_var("SIGUL_PESIGN_BRIDGE_LOG")
        .with_default_directive(LevelFilter::INFO.into())
        .from_env()
        .context(
            "SIGUL_PESIGN_BRIDGE_LOG contains an invalid log directive; refer to \
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

    let halt_token = CancellationToken::new();
    tokio::spawn(signal_handler(halt_token.clone()));

    match opts.command {
        cli::Command::Listen { runtime_directory } => {
            // if multiple runtime directories were provided, we don't know which to use so panic for now.
            if runtime_directory
                .to_str()
                .ok_or(anyhow::anyhow!(
                    "runtime_directory must be valid unicode characters"
                ))?
                .contains(':')
            {
                return Err(anyhow::anyhow!(
                    "Multiple RuntimeDirectories are not supported"
                ));
            }
            let config = opts.config.unwrap_or_default();
            config.validate().context(
                "configuration format is correct, but references files that are missing or invalid",
            )?;

            service::listen(runtime_directory, config, halt_token)?.await?
        }
        cli::Command::Config => {
            let config = opts.config.unwrap_or_default();
            println!("Current configuration:\n\n{}", config);
            config.validate().inspect_err(|err|{
                eprintln!("The configuration format is correct, but references files that are missing or invalid: {}", err);
            })
        }
    }
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
        tracing::error!(?error, "Failed to register a SIGTERM signal handler")
    })?;
    let mut sigint_stream = signal(SignalKind::interrupt()).inspect_err(|error| {
        tracing::error!(?error, "Failed to register a SIGINT signal handler")
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
