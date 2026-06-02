// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

/*!
# Siguldry

Siguldry is a replacement for Fedora's software signing service, [Sigul][1]. It is heavily inspired
by Sigul, but includes a few protocol changes based on how Sigul is currently used in Fedora, which
is significantly different from how it was originally envisioned when Sigul was designed.

In addition to the protocol level change, Siguldry also supports a greatly reduced set of commands.

<div class="warning">This crate is still under active development and there will be several more
rounds of breaking changes to the Rust API before a 1.0 release is made. Command-line interfaces are
expected to remain stable.</div>

## Components

The service includes three components. The first part, the server, is responsible for keeping the
signing keys safe and for servicing client requests for signatures. The server does not listen on
any network interfaces and will only send outgoing TCP connections to the configured bridge.

The bridge is a proxy. It accepts connections from servers and clients, which are both
authenticated using mutual TLS certificates, and then ferries client and server traffic between the
two connections. This ensures only clients with valid TLS certificates can even initialize a
connection to the server.

The final component is the client which lets users request signatures from the server. It is
recommended that end users make use of the `libsiguldry_pkcs11.so` PKCS#11 module provided by the
[siguldry-pkcs11][2] crate for signing needs rather than using the client directly.

Additionally, this crate provides a legacy [Sigul][1] client that is compatible with version
1.2+.

## Crate features

By default, the server, bridge, and client for Siguldry along with their CLIs is built.

* **cli** -
  Include the experimental Siguldry CLIs. This is a default feature.

* **server** -
  Include the experimental Siguldry server APIs. This is a default feature.

* **sigul-client** -
  Include the client compatible with Sigul 1.2. This is not enabled by default.

[1]: https://pagure.io/sigul
[2]: https://crates.io/crates/siguldry-pkcs11
*/

#[cfg(feature = "otel")]
use anyhow::Context;
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;
#[cfg(feature = "otel")]
use tracing_subscriber::Layer;

#[cfg(feature = "sigul-client")]
mod serdes;
#[cfg(feature = "sigul-client")]
pub mod v1;

pub mod bridge;
pub mod client;
pub mod config;
#[doc(hidden)]
pub mod der;
pub mod error;
mod ipc_common;
pub(crate) mod nestls;
pub mod protocol;
#[cfg(feature = "server")]
pub mod server;

/// Install and manage signal handlers for the process.
///
/// # SIGTERM and SIGINT
///
/// Sending SIGTERM or SIGINT to the process will cause it to stop accepting new
/// signing requests. Existing signing requests will be allowed to complete
/// before the process shuts down.
#[doc(hidden)]
pub async fn signal_handler(halt_token: CancellationToken) -> Result<(), anyhow::Error> {
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

/// Initialize an OpenTelemetry tracing layer that exports spans via a Tonic client
///
/// Returns a guard that shuts down the tracer provider on drop, along with
/// the layer to register with the tracing subscriber. If no endpoint is
/// provided, both are `None`.
#[cfg(feature = "otel")]
#[doc(hidden)]
pub fn init_otel(
    endpoint: Option<&str>,
    name: &'static str,
) -> anyhow::Result<(
    Option<OtelGuard>,
    Option<impl Layer<tracing_subscriber::Registry>>,
)> {
    use opentelemetry::trace::TracerProvider;
    use opentelemetry_otlp::WithExportConfig;
    let endpoint = if let Some(endpoint) = endpoint {
        endpoint
    } else {
        return Ok((None, None));
    };

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .context("Failed to create OTLP span exporter")?;

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_sampler(opentelemetry_sdk::trace::Sampler::AlwaysOn)
        .with_batch_exporter(exporter)
        .build();

    let tracer = provider.tracer(name);
    let layer = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing::info!(endpoint, "OpenTelemetry OTLP export enabled");
    Ok((Some(OtelGuard(provider)), Some(layer)))
}

#[cfg(feature = "otel")]
#[doc(hidden)]
pub struct OtelGuard(opentelemetry_sdk::trace::SdkTracerProvider);

#[cfg(feature = "otel")]
impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Err(error) = self
            .0
            .shutdown_with_timeout(std::time::Duration::from_secs(5))
        {
            tracing::error!(?error, "Failed to shut down the OpenTelemetry exporter");
        }
    }
}
