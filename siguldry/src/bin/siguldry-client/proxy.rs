use std::{os::unix::fs::PermissionsExt, path::PathBuf};

use anyhow::{Context, anyhow};
use siguldry::{client::Client, protocol};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    task::JoinHandle,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::Instrument;

pub fn listen(
    client: Client,
    socket_path: PathBuf,
    halt_token: CancellationToken,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("Failed to bind to {}", &socket_path.display()))?;
    let metadata = std::fs::metadata(&socket_path)?;
    if metadata.permissions().mode() & rustix::fs::Mode::RWXO.bits() != 0 {
        tracing::error!(mode=?metadata.permissions(), "Service socket has dangerous permissions!");
        std::fs::remove_file(&socket_path)
            .with_context(|| format!("Failed to remove socket {}", &socket_path.display()))?;
        return Err(anyhow!(
            "Other users have access to the socket, adjust the service umask!"
        ));
    }
    tracing::info!(socket=?socket_path, mode=?metadata.permissions(), "Listening");

    let request_tracker = TaskTracker::new();
    Ok(tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = halt_token.cancelled() => {
                    tracing::info!(socket=?socket_path, "Shutdown requested, no new requests will be accepted");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((unix_stream, _)) => {
                            request_tracker.spawn(request_handler(client.clone(), unix_stream).instrument(tracing::Span::current()));
                        },
                        Err(error) => {
                            tracing::error!(socket=?socket_path, ?error, "Failed to accept request");
                        },
                    }
                }
            }
        }

        // Remove the socket and then wait for any requests in progress to complete before
        // exiting.
        std::fs::remove_file(&socket_path)
            .with_context(|| format!("Failed to remove socket {}", &socket_path.display()))?;
        tracing::debug!(socket=?socket_path, "Successfully removed socket");
        tracing::info!(
            pending_requests = request_tracker.len(),
            "Waiting for pending requests to complete"
        );
        request_tracker.close();
        request_tracker.wait().await;

        Ok(())
    }.instrument(tracing::Span::current())))
}

async fn request_handler(client: Client, mut unix_stream: UnixStream) -> anyhow::Result<()> {
    let (reader, mut writer) = unix_stream.split();
    let reader = BufReader::new(reader);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let request: protocol::json::Request = serde_json::from_str(&line)?;

        match request {
            protocol::json::Request::SignPrehashed { key, digests } => {
                let signatures = client.sign_prehashed(key, digests).await?;
                let result =
                    serde_json::to_string(&protocol::json::Response::SignPrehashed { signatures })?;
                writer.write_all(result.as_bytes()).await?;
                writer.write("\n".as_bytes()).await?;
            }
            _ => {
                tracing::error!("Unsupported operation")
            }
        }
    }

    Ok(())
}
