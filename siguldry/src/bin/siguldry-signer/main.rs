// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! This is a helper binary that is run per-connection and is the process that performs the
//! actual signing.
//!
//! Requests are sent over stdin as JSON separated by newlines.
//! Responses are sent over stdout as JSON separated by newlines.

use std::{collections::HashMap, io::Write, path::PathBuf};

use anyhow::{Context, anyhow};
use clap::Parser;
use cryptoki::types::AuthPin;
use sequoia_openpgp::{
    KeyHandle,
    crypto::Password,
    parse::Parse,
    policy::StandardPolicy,
    serialize::stream::{LiteralWriter, Message, Signer as PgpSigner},
};
use siguldry::{
    protocol::{DigestAlgorithm, GpgSignatureType, json::Signature},
    server::{
        Config, crypto,
        db::{self, User},
        ipc,
    },
    signal_handler,
};
use sqlx::SqliteConnection;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;
use tracing::instrument;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan, layer::SubscriberExt};
use uuid::Uuid;

/// Helper binary for the Siguldry server; this is not intended to be called directly.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    #[arg(long)]
    working_dir: PathBuf,

    /// A set of one or more comma-separated directives to filter logs.
    ///
    /// The general format is "target_name[span_name{field=value}]=level" where level is
    /// one of TRACE, DEBUG, INFO, WARN, ERROR.
    ///
    /// Details: https://docs.rs/tracing-subscriber/0.3.19/tracing_subscriber/filter/struct.EnvFilter.html#directives
    #[arg(long, default_value = "INFO")]
    pub log_filter: String,

    #[arg(long)]
    pub session_id: Uuid,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let opts = Cli::parse();

    // Unfortunately we can't use clap's value_parser since EnvFilter does not
    // implement Clone.
    let log_filter = EnvFilter::builder().parse(&opts.log_filter).context(
        "SIGULDRY_SERVER_LOG contains an invalid log directive; refer to \
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

    handle(opts).await
}

#[instrument(name = "siguldry-signer", fields(session_id = opts.session_id.to_string()))]
async fn handle(opts: Cli) -> anyhow::Result<()> {
    let session_id = opts.session_id.to_string();
    let mut requests = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();

    let halt_token = CancellationToken::new();
    tokio::spawn(signal_handler(halt_token.clone()));

    // Keys that the client has unlocked are stored in this map of key names to key passwords.
    // A performance optimization might be to decrypt the key once; we should benchmark and
    // decide on that.
    let mut key_passwords: HashMap<String, Password> = HashMap::new();
    let (user, config) = tokio::select! {
        _ = halt_token.cancelled() => {
            tracing::info!("siguldry-helper received shut down signal");
            return Ok(())
        }
        request = requests.next_line() => {
            match request? {
                Some(request) => {
                    let request: ipc::Request = serde_json::from_str(&request)?;
                    match request {
                        ipc::Request::Config { user, config } => {
                            let mut response = serde_json::to_string(&ipc::Response::Success {  })?;
                            response.push('\n');
                            stdout.write_all(response.as_bytes()).await?;
                            (user, config)},
                        _ => return Err(anyhow!("The first message must configure this helper"))
                    }
                },
                None => return Ok(())
            }
        }
    };

    let db_pool = db::pool(
        config
            .database()
            .as_os_str()
            .to_str()
            .ok_or_else(|| anyhow!("Database path isn't valid UTF8"))?,
        true,
    )
    .await?;
    let mut db_conn = db_pool.acquire().await?;
    let user = db::User::get(&mut db_conn, &user).await?;
    drop(db_conn);
    tracing::debug!(
        session_id,
        user.name,
        "siguldry-signer is configured and ready to use"
    );

    loop {
        let request = tokio::select! {
            _ = halt_token.cancelled() => {
                tracing::info!("siguldry-signer received shut down signal");
                break;
            }
            request = requests.next_line() => request,
        }?;
        tracing::debug!(session_id, "siguldry-signer got request");

        let request = if let Some(request) = request {
            serde_json::from_str(&request)?
        } else {
            tracing::info!("siguldry-signer received EOF and is shutting down");
            break;
        };

        let response = match request {
            ipc::Request::Config { user: _, config: _ } => ipc::Response::Failure {
                reason: "helper cannot be configured twice".to_string(),
            },
            ipc::Request::Unlock { key, password } => {
                let mut conn = db_pool.begin().await?;
                match unlock(
                    &mut conn,
                    &mut key_passwords,
                    &config,
                    &user,
                    key,
                    Password::from(password),
                )
                .await
                {
                    Ok(_) => ipc::Response::Success {},
                    Err(error) => ipc::Response::Failure {
                        reason: error.to_string(),
                    },
                }
            }
            ipc::Request::Sign { key, digests } => {
                let mut conn = db_pool.begin().await?;
                match sign(&mut conn, &mut key_passwords, &key, digests).await {
                    Ok(signatures) => ipc::Response::Signatures { signatures },
                    Err(error) => ipc::Response::Failure {
                        reason: error.to_string(),
                    },
                }
            }
            ipc::Request::PgpSign {
                key,
                signature_type,
                payload_size,
            } => {
                let mut inner = requests.into_inner();
                let mut buffer = vec![0; payload_size];
                inner.read_exact(&mut buffer).await?;
                requests = inner.lines();

                let mut conn = db_pool.begin().await?;
                let (response, signature) =
                    pgp_sign(&mut conn, &key_passwords, &key, signature_type, buffer).await?;
                tracing::trace!("Finished signing request");

                let mut response = serde_json::to_string(&response)?;
                response.push('\n');
                stdout.write_all(response.as_bytes()).await?;
                tracing::trace!("Finished writing pgp_sign json response");
                stdout.write_all(&signature).await?;
                stdout.flush().await?;
                tracing::trace!(
                    payload_len = signature.len(),
                    "Finished writing pgp_sign signature"
                );
                continue;
            }
        };
        tracing::trace!("About to write response");
        let mut response = serde_json::to_string(&response)?;
        response.push('\n');
        stdout.write_all(response.as_bytes()).await?;
        tracing::trace!("Successfully wrote response");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[instrument(skip_all, err, fields(key = key_name))]
async fn unlock(
    conn: &mut SqliteConnection,
    key_passwords: &mut HashMap<String, Password>,
    config: &Config,
    user: &User,
    key_name: String,
    user_password: Password,
) -> anyhow::Result<()> {
    let key = db::Key::get(conn, &key_name).await?;
    let key_access = db::KeyAccess::get(conn, &key, user).await?;
    let password = crypto::decrypt_key_password(
        &config.pkcs11_bindings,
        user_password,
        &key_access.encrypted_passphrase,
    )
    .await?;
    key_passwords.insert(key.name, password);
    return Ok(());
}

#[instrument(skip_all, err, fields(key = key_name))]
async fn sign(
    conn: &mut SqliteConnection,
    key_passwords: &mut HashMap<String, Password>,
    key_name: &str,
    digests: Vec<(DigestAlgorithm, String)>,
) -> anyhow::Result<Vec<Signature>> {
    let key = db::Key::get(conn, key_name).await?;
    let password = key_passwords
        .get(key_name)
        .ok_or_else(|| anyhow!("You need to unlock the key"))?;

    let signatures = if let Some(token_id) = key.pkcs11_token_id {
        // For PKCS#11 keys, fetch the token information and use the configured PIN
        let token = db::Pkcs11Token::get(conn, token_id).await?;
        let pin = password
            .map(|p| String::from_utf8(p.to_vec()))
            .map(AuthPin::from)?;
        crypto::sign_with_pkcs11(&key, &token, &pin, digests)?
    } else {
        crypto::sign_with_softkey(&key, password, digests)?
    };

    Ok(signatures)
}

#[instrument(skip_all, err, fields(key = key_name))]
async fn pgp_sign(
    conn: &mut SqliteConnection,
    keystore: &HashMap<String, Password>,
    key_name: &str,
    signature_type: GpgSignatureType,
    blob: Vec<u8>,
) -> anyhow::Result<(ipc::Response, Vec<u8>)> {
    let key = db::Key::get(conn, key_name).await?;
    let password = keystore
        .get(key_name)
        .ok_or_else(|| anyhow::anyhow!("Key must be unlocked before signing"))?;
    let cert = sequoia_openpgp::Cert::from_bytes(&key.key_material)?;
    let policy = &StandardPolicy::new();
    let signing_key = cert
        .keys()
        .secret()
        .with_policy(policy, None)
        .supported()
        .for_signing()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No signing-capable key found in certificate"))?
        .key()
        .clone()
        .decrypt_secret(password)?
        .into_keypair()?;
    let key_handle: KeyHandle = key.handle.parse()?;
    tracing::debug!(handle=?key_handle, "keystore found key");

    let signature = {
        let mut sink = vec![];
        let signer = PgpSigner::new(Message::new(&mut sink), signing_key)?;
        let mut message = match signature_type {
            GpgSignatureType::Detached => signer.detached().build()?,
            GpgSignatureType::Cleartext => signer.cleartext().build()?,
            GpgSignatureType::Inline => LiteralWriter::new(signer.build()?).build()?,
            _ => panic!("Unknown signature type requested"),
        };

        message.write_all(&blob)?;
        message.finalize()?;
        tracing::trace!("Successfully signed message");
        Ok::<_, anyhow::Error>(sink)
    }?;

    let response = ipc::Response::PgpSign {
        payload_size: signature.len(),
    };

    Ok((response, signature))
}
