// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::process::Stdio;
use std::time::Duration;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tracing::instrument;
use uuid::Uuid;

use crate::error::ServerError;
use crate::protocol::{self, GpgSignatureType};
use crate::{
    protocol::{DigestAlgorithm, json::Signature},
    server::Config,
};

#[derive(Serialize, Deserialize)]
#[allow(clippy::exhaustive_enums)]
#[doc(hidden)]
pub enum Request {
    Config {
        user: String,
        config: Config,
    },
    Unlock {
        key: String,
        password: String,
    },
    Sign {
        key: String,
        digests: Vec<(DigestAlgorithm, String)>,
    },
    PgpSign {
        key: String,
        signature_type: GpgSignatureType,
        payload_size: usize,
    },
}

#[derive(Serialize, Deserialize)]
#[allow(clippy::exhaustive_enums)]
#[doc(hidden)]
pub enum Response {
    Signatures { signatures: Vec<Signature> },
    PgpSign { payload_size: usize },
    Success {},
    Failure { reason: String },
}

pub(crate) struct Server {
    child: Child,
    requests: ChildStdin,
    responses: Option<Lines<BufReader<ChildStdout>>>,
    service_unit: String,
    _working_dir: TempDir,
}

impl Server {
    pub(crate) async fn new(
        user: String,
        config: Config,
        working_dir: TempDir,
        session_id: Uuid,
    ) -> anyhow::Result<Self> {
        let service_unit = format!("siguldry-signer-{session_id}.service");
        let mut helper = tokio::process::Command::new("systemd-run");
        helper
            .arg("--pipe")
            .arg("--user")
            .arg("--same-dir")
            .arg("--collect")
            .arg(format!("--unit=siguldry-signer-{session_id}"))
            // Communication happens exclusively over the piped stdin/stdout
            .arg("--property=PrivateNetwork=true")
            .arg("--property=CapabilityBoundingSet=")
            // Kernel protection
            .arg("--property=ProtectKernelTunables=true")
            .arg("--property=ProtectKernelModules=true")
            .arg("--property=ProtectKernelLogs=true")
            .arg("--property=ProtectControlGroups=true")
            .arg("--property=ProtectClock=true")
            .arg("--property=ProtectHostname=true")
            // Process isolation
            .arg("--property=NoNewPrivileges=true")
            .arg("--property=LockPersonality=true")
            .arg("--property=RestrictRealtime=true")
            .arg("--property=RestrictSUIDSGID=true")
            .arg("--property=RestrictNamespaces=true")
            .arg("--property=RemoveIPC=true")
            // System call filtering
            .arg("--property=SystemCallFilter=@system-service")
            .arg("--property=SystemCallArchitectures=native")
            .arg("--property=SystemCallErrorNumber=EPERM")
            //// Filesystem restrictions
            .arg("--property=ProtectSystem=strict")
            .arg("--property=ProtectProc=invisible")
            .arg(format!(
                "--property=ReadWritePaths={}",
                working_dir.path().display()
            ))
            .arg(format!(
                "--property=ReadOnlyPaths={}",
                config.state_directory.display()
            ))
            .arg("--property=NoExecPaths=/")
            .arg(format!(
                "--property=ExecPaths={} /usr/bin/openssl /usr/libexec/sequoia-keystore /usr/lib /usr/lib64",
                &config.signer_executable.display(),
            ))
            .arg("--")
            .arg(&config.signer_executable)
            .arg("--session-id")
            .arg(session_id.to_string())
            .arg("--log-filter")
            .arg(std::env::var("SIGULDRY_SERVER_LOG").unwrap_or("WARN".to_string()))
            .arg("--working-dir")
            .arg(working_dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true);

        let mut child = helper.spawn()?;
        let requests = child
            .stdin
            .take()
            .expect("helper must be configured with stdin");
        let responses = child
            .stdout
            .take()
            .expect("helper must be configured with stdout");
        let responses = Some(BufReader::new(responses).lines());

        let mut server = Self {
            child,
            requests,
            responses,
            service_unit,
            _working_dir: working_dir,
        };
        tracing::trace!("requesting signing helper config");
        server.request(&Request::Config { user, config }).await?;
        tracing::trace!("requested signing helper config");

        Ok(server)
    }

    async fn request(&mut self, request: &Request) -> anyhow::Result<Response> {
        let mut request = serde_json::to_string(request)?;
        request.push('\n');
        self.requests.write_all(request.as_bytes()).await?;

        match self.responses.as_mut().unwrap().next_line().await? {
            Some(response) => Ok(serde_json::from_str(&response)?),
            None => Err(anyhow::anyhow!("IPC server returned EOF unexpectedly!")),
        }
    }

    #[instrument(skip_all, err, fields(key))]
    pub(crate) async fn unlock_request(
        &mut self,
        key: String,
        password: String,
    ) -> Result<protocol::Response, ServerError> {
        let response = self.request(&Request::Unlock { key, password }).await?;

        match response {
            Response::Failure { reason } => {
                tracing::error!(reason, "Failed to unlock key");
                Err(ServerError::Internal)
            }
            Response::Success {} => Ok(protocol::json::Response::Unlock {}.into()),
            _ => {
                tracing::error!("helper returned invalid response");
                Err(ServerError::Internal)
            }
        }
    }

    #[instrument(skip_all, err, fields(key))]
    pub(crate) async fn sign_request(
        &mut self,
        key: String,
        digests: Vec<(DigestAlgorithm, String)>,
    ) -> Result<Vec<Signature>, ServerError> {
        let response = self.request(&Request::Sign { key, digests }).await?;

        match response {
            Response::Signatures { signatures } => Ok(signatures),
            Response::Failure { reason } => {
                tracing::error!(reason, "Failed to unlock key");
                Err(ServerError::Internal)
            }
            _ => {
                tracing::error!("helper returned invalid response");
                Err(ServerError::Internal)
            }
        }
    }

    #[instrument(skip_all, err, fields(key, signature_type))]
    pub(crate) async fn pgp_sign_request(
        &mut self,
        key: String,
        signature_type: GpgSignatureType,
        blob: Bytes,
    ) -> anyhow::Result<protocol::Response> {
        let payload_size = blob.len();
        let mut request = serde_json::to_string(&Request::PgpSign {
            key,
            signature_type,
            payload_size,
        })?;
        request.push('\n');
        self.requests.write_all(request.as_bytes()).await?;
        self.requests.write_all(&blob).await?;
        self.requests.flush().await?;

        let payload_size = match self.responses.as_mut().unwrap().next_line().await {
            Ok(Some(response)) => {
                let response: Response = serde_json::from_str(&response)?;
                match response {
                    Response::PgpSign { payload_size } => Ok(payload_size),
                    Response::Failure { reason } => {
                        tracing::error!(reason, "Failed to unlock key");
                        Err(ServerError::Internal)
                    }
                    _ => {
                        tracing::error!("helper returned invalid response");
                        Err(ServerError::Internal)
                    }
                }
            }
            Ok(None) => todo!(),
            Err(_) => todo!(),
        }?;
        tracing::info!(payload_size, "helper response received");

        let mut inner = self.responses.take().unwrap().into_inner();
        let mut buffer = vec![0; payload_size];
        tracing::info!(len = buffer.len(), "trying to read into buf");
        let result = inner.read_exact(&mut buffer).await;
        tracing::info!(payload_size, "signature read");
        self.responses = Some(inner.lines());
        result?;

        let response = protocol::Response {
            json: protocol::json::Response::GpgSign {},
            binary: Some(Bytes::from(buffer)),
        };

        Ok(response)
    }

    /// Shut down the IPC server.
    ///
    /// Failing to call this will result in leaking systemd scopes
    pub(crate) async fn shutdown(mut self) -> anyhow::Result<()> {
        self.requests.shutdown().await?;
        let status = tokio::process::Command::new("systemctl")
            .arg("--user")
            .arg("--no-block")
            .arg("stop")
            .arg(&self.service_unit)
            .status()
            .await?;

        if !status.success() {
            tracing::warn!(unit = %self.service_unit, "Failed to stop systemd scope");
        }
        let _ = tokio::time::timeout(Duration::from_millis(500), self.child.kill()).await;

        Ok(())
    }
}
