// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! A minimal pesign daemon implementation.
//!
//! This handles requests from pesign clients to sign PE applications, but only if
//! the request is for attached signatures and the client provides the file type. This
//! should be the case for reasonably up-to-date pesign clients requesting a signature.
//!
//! Other commands supported by the pesign daemon such at unlocking tokens are not
//! supported.

use std::{
    fs::File,
    io::{self, IoSliceMut},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, RawFd},
        unix::fs::PermissionsExt,
    },
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{anyhow, Context};
use bytes::Bytes;
use nix::{
    cmsg_space,
    sys::{
        socket::{ControlMessageOwned, MsgFlags, UnixAddr},
        stat::Mode,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    task::JoinHandle,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{instrument, Instrument};

use crate::{
    config::{Config, Key},
    pesign::{self, Command, Header, Response, SignAttachedRequest},
};

/// Listen on a Unix socket on the given path.
///
/// This function will bind the socket and check its permissions,
/// then spawn an asynchronous worker to handle requests. To stop
/// the worker, cancel the given `halt_token` and then await the
/// returned [`JoinHandle`].
///
/// Pending requests will be allowed to complete before the task
/// completes.
#[doc(hidden)]
#[instrument(err, skip_all)]
pub fn listen(
    runtime_directory: PathBuf,
    config: Config,
    halt_token: CancellationToken,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    let socket_path = runtime_directory.join("socket");
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("Failed to bind to {}", &socket_path.display()))?;
    let metadata = std::fs::metadata(&socket_path)?;
    if metadata.permissions().mode() & Mode::S_IRWXO.bits() != 0 {
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
                            request_tracker.spawn(request(runtime_directory.clone(), config.clone(), unix_stream).instrument(tracing::Span::current()));
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

/// Process a single client request.
///
/// All requests are wrapped in a timeout to ensure they don't get stuck forever.
/// This timeout is configurable via [`Config::request_timeout_secs`].
#[instrument(skip_all, ret, fields(request_id = uuid::Uuid::now_v7().to_string()))]
async fn request(
    runtime_directory: PathBuf,
    config: Config,
    unix_stream: UnixStream,
) -> Result<(), anyhow::Error> {
    let result = tokio::time::timeout(
        Duration::from_secs(config.request_timeout_secs.get()),
        request_handler(runtime_directory, config, unix_stream),
    )
    .await;
    if result.is_err() {
        tracing::error!("Request handler timed out!");
    }

    result?
}

async fn request_handler(
    runtime_directory: PathBuf,
    config: Config,
    mut unix_stream: UnixStream,
) -> Result<(), anyhow::Error> {
    loop {
        // Read the command header, which gives us the requested command and payload size.
        let mut buf = [0_u8; pesign::PESIGN_HEADER_SIZE];
        match unix_stream.read_exact(&mut buf).await {
            Ok(_bytes_read) => {
                let request: Header = buf.as_slice().try_into()?;
                tracing::debug!(?request, "Client request received");

                match request.command {
                    Command::GetCmdVersion => {
                        get_command_version(&mut unix_stream, request.payload_length).await
                    }
                    Command::SignAttachedWithFileType => {
                        let result = sign_attached_with_filetype(
                            &runtime_directory,
                            &config,
                            &mut unix_stream,
                            request.payload_length,
                        )
                        .await;
                        let mut response: Bytes = Response::from(&result).into();
                        unix_stream.write_all_buf(&mut response).await?;

                        result
                    }
                    _unsupported => {
                        // A well-behaved client should never do this: it queries for the command version
                        // and we respond indicating we don't know it.
                        tracing::error!(?request, "Client requested unsupported command; ignoring");
                        return Err(anyhow!("Client is misbehaving"));
                    }
                }?;
            }
            Err(ref error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                tracing::debug!("Client sent EOF; hanging up");
                break;
            }
            Err(error) => {
                tracing::error!(?error, "Failed to read client request");
                break;
            }
        }
    }

    Ok(())
}

/// Return the version of the command described in the payload.
///
/// pesign commands are currently all version 0, so we return that since we will
/// implement our own interface if we opt to adjust things. This does mean newer
/// versions of pesign might not work with us, but since the client queries for
/// [`PESIGND_VERSION`] it will at least be clear why.
///
/// This also return -1 for commands we don't support so the client gets a clear
/// error when attempting such commands.
#[instrument(skip_all, ret)]
async fn get_command_version(
    connection: &mut UnixStream,
    payload_length: usize,
) -> Result<(), anyhow::Error> {
    if payload_length != 4 {
        return Err(anyhow!("Payload size for get-cmd-version should be 4"));
    }

    let mut payload = [0_u8; 4];
    connection.read_exact(&mut payload).await?;

    let command = u32::from_ne_bytes(payload);

    match Command::try_from(command) {
        Ok(Command::GetCmdVersion | Command::SignAttachedWithFileType) => {
            tracing::debug!(
                "Client queried for the server version of command {:?}",
                command
            );
            let mut response: Bytes = Response::Success.into();
            connection.write_all_buf(&mut response).await?;
            Ok(())
        }
        Ok(command) => {
            tracing::warn!(
                "Client queried for the server version of command {:?}, which is not supported",
                command
            );
            let mut response: Bytes = Response::Failure.into();
            connection.write_all_buf(&mut response).await?;
            Ok(())
        }
        Err(error) => {
            tracing::error!(
                error = ?error,
                command = "get-cmd-version",
                queried_command = command,
                "Unknown command version requested"
            );
            let mut response: Bytes = Response::Failure.into();
            connection.write_all_buf(&mut response).await?;
            return Err(anyhow!("get-cmd-version request was malformed"));
        }
    }
}

struct PesignFiles {
    unsigned_input: File,
    signed_output: File,
}

impl From<[File; 2]> for PesignFiles {
    fn from(value: [File; 2]) -> Self {
        // pesign sends the input file descriptor first, then the output file descriptor.
        let [unsigned_input, signed_output] = value;
        Self {
            unsigned_input,
            signed_output,
        }
    }
}

// Helper to get the file descriptors pesign-client sends over the Unix socket.
//
// Both the Rust standard library and tokio don't include support for ancillary data
// over Unix sockets. Instead, we use the nix library's blocking interface to retrieve
// the file descriptors from the client.
//
// https://github.com/rust-lang/rust/issues/76915
async fn get_files_from_conn(connection: &mut UnixStream) -> anyhow::Result<PesignFiles> {
    let raw_fd = connection.as_fd().as_raw_fd();
    let span = tracing::Span::current();
    tokio::task::spawn_blocking(move || {
        let _entered = span.enter();
        let mut cmsgs = vec![];

        // First one is fdin, second is fdout
        let mut tries = 0;
        while cmsgs.len() < 2 {
            let mut buf = [0_u8; 2];
            let mut b = [IoSliceMut::new(&mut buf)];
            let mut cmsg_buffer = cmsg_space!([RawFd; 1]);
            let result = match nix::sys::socket::recvmsg::<UnixAddr>(
                raw_fd,
                &mut b,
                Some(&mut cmsg_buffer),
                MsgFlags::MSG_WAITALL,
            ) {
                Ok(message) => message,
                Err(nix::errno::Errno::EAGAIN) => {
                    if tries > 10 {
                        return Err(anyhow!(
                            "Timed out waiting for client to send file descriptors to sign"
                        ));
                    }
                    tracing::trace!("Got EAGAIN when retrieving file descriptors for signing");
                    std::thread::sleep(Duration::from_millis(25));
                    tries += 1;
                    continue;
                }
                Err(error) => {
                    tracing::error!(?error, "Failed to read client request");
                    return Err(anyhow!("Failed to read client request: {:?}", error));
                }
            };
            let mut cmsg = result
                .cmsgs()
                .context("Not enough space was allocated for control messages")?
                .collect::<Vec<_>>();
            tracing::debug!(
                ?cmsg,
                "Read control message from client with file descriptor"
            );
            cmsgs.append(&mut cmsg);

            // We don't expect any more data beyond the file descriptors so if there's any non-null bytes
            // something has changed.
            if result.iovs().flatten().any(|b| *b != 0) {
                tracing::error!("Unexpected non-null data found with control message; aborting");
                return Err(anyhow!("Unexpected data provided by the client"));
            }
        }

        convert_cmsgs_to_files(cmsgs)
    })
    .await?
}

// Take the control messages and convert the raw file descriptors to [`PesignFiles`].
fn convert_cmsgs_to_files(cmsgs: Vec<ControlMessageOwned>) -> anyhow::Result<PesignFiles> {
    let mut files = vec![];
    for cmsg in cmsgs {
        match cmsg {
            nix::sys::socket::ControlMessageOwned::ScmRights(fds) => {
                if fds.len() != 1 {
                    return Err(anyhow!("Unexpected number of file descriptors sent"));
                }

                let file = fds
                    .first()
                    .map(|fd| {
                        let raw_fd = RawFd::from(*fd);

                        // Do our best to check this is a valid descriptor
                        let flags = nix::fcntl::fcntl(raw_fd, nix::fcntl::F_GETFL)
                            .context("Client passed invalid file descriptor")?;
                        tracing::debug!(
                            "Client sent file descriptor {raw_fd} with flags: {flags:#o}"
                        );

                        // SAFETY:
                        // The file descriptor has been passed to us from the Unix socket and we own
                        // the descriptor. We've done what we can to ensure the descriptor is, in
                        // fact, valid.
                        Ok::<_, anyhow::Error>(unsafe { File::from_raw_fd(raw_fd) })
                    })
                    .ok_or(anyhow!(
                        "Programmer error: there should be 1 file descriptor"
                    ))??;

                files.push(file);
            }
            _ => return Err(anyhow!("Unexpected control message received")),
        }
    }

    let files: [File; 2] = files
        .try_into()
        .map_err(|error| anyhow!("Client did not send the expected number of files: {error:?}"))?;
    Ok(files.into())
}

/// Handle signing requests from the pesign-client.
///
/// # Example
///
/// $ pesign-client --sign \
///     --token="my token" \
///     --certificate="my certificate" \
///     --infile="README.md" \
///     --outfile="README.md.signed"
///
/// In this example, the service configuration must contain a [`Key`] with
/// `key_name = "my token"` and `certificate_name = "my certificate"` or it will
/// respond to the client request with a failure.
#[instrument(skip_all, ret)]
async fn sign_attached_with_filetype(
    runtime_directory: &Path,
    config: &Config,
    connection: &mut UnixStream,
    payload_length: usize,
) -> Result<(), anyhow::Error> {
    let mut payload = vec![0_u8; payload_length];
    connection.read_exact(&mut payload).await?;
    tracing::trace!(?payload_length, ?payload, "Read payload");

    let request = SignAttachedRequest::try_from(payload.as_slice())?;
    tracing::info!(?request.token_name, ?request.certificate_name, "Client signing request received");

    let key = request.key(&config.keys)?;
    let mut pesign_files = get_files_from_conn(connection).await?;

    let temp_dir = tempfile::Builder::new()
        .prefix(".work")
        .rand_bytes(16)
        .tempdir_in(runtime_directory)
        .inspect_err(|error| {
            tracing::error!(
                ?error,
                ?runtime_directory,
                "Failed to make temporary directory inside the runtime directory"
            );
        })?;
    let sigul_input = temp_dir.path().join("unsigned_file");
    let sigul_output = temp_dir.path().join("signed_file");

    let span = tracing::Span::current();
    let sigul_input = tokio::task::spawn_blocking(move || {
        let _enter = span.enter();
        let mut sigul_input_file = std::fs::File::options().create(true).write(true).truncate(true).open(&sigul_input).inspect_err(|error| {
            tracing::error!(?error, path=?sigul_input, "Failed to open the temporary file used for sigul input");
        })?;
        let input_bytes = std::io::copy(&mut pesign_files.unsigned_input, &mut sigul_input_file).inspect_err(|error| {
            tracing::error!(?error, path=?sigul_input, "Failed to copy the input file to a temporary file for sigul input")
        })?;
        tracing::info!(input_bytes, "Forwarding PE file to Sigul for signing");

        Ok::<_, anyhow::Error>(sigul_input)
    }).await??;

    let sigul_client_config = config.sigul_client_config()?;
    tokio::time::timeout(
        // Grant the service 500 milliseconds to send the final "we failed message"
        Duration::from_secs_f64(config.request_timeout_secs.get() as f64 - 0.5),
        async {
            while let Err(error) =
                forward_pe_file(&sigul_client_config, key, &sigul_input, &sigul_output).await
            {
                tracing::warn!(%error, "signing failed; retrying sigul client in 2 seconds");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        },
    )
    .await
    .context("Timeout reached while waiting for Sigul")?;

    if let Some(signing_cert) = &key.certificate_file {
        tracing::info!("Certificate file is provided for this key; validating with 'sbverify'");
        let mut command = tokio::process::Command::new("sbverify");
        command
            .arg("--cert")
            .arg(signing_cert)
            .arg(&sigul_output)
            .kill_on_drop(true);
        let result = tokio::time::timeout(Duration::from_secs(5), command.output()).await;
        match result {
            Ok(Ok(output)) => {
                if output.status.success() {
                    tracing::info!("PE file signature validated");
                } else {
                    tracing::error!(?output, "PE file is not signed as expected!");
                    return Err(anyhow!("PE file failed signature validation"));
                }
            }
            Ok(Err(error)) => {
                tracing::error!(?error, ?command, "Unable to run sbverify command");
                return Err(anyhow!(
                    "PE file signature validation requested, but failed to run"
                ));
            }
            Err(_error) => {
                tracing::error!(?command, "Command failed to finish withint 5 seconds");
                return Err(anyhow!(
                    "PE file signature validation requested, but timed out"
                ));
            }
        }
    }

    let span = tracing::Span::current();
    tokio::task::spawn_blocking(move || {
        let _enter = span.enter();
        let mut sigul_output_file = std::fs::File::options().create(false).read(true).open(&sigul_output).inspect_err(|error| {
            tracing::error!(?error, path=?sigul_output, "Failed to open the temporary file used for sigul output");
        })?;
        let output_bytes = std::io::copy(&mut sigul_output_file, &mut pesign_files.signed_output).inspect_err(|error| {
            tracing::error!(?error, path=?sigul_input, "Failed to copy the sigul output file to the pesign input")
        })?;
        tracing::info!(output_bytes, "Signing request completed");
        Ok::<_, anyhow::Error>(())
    }).in_current_span().await??;

    Ok(())
}

#[instrument(skip_all, ret)]
async fn forward_pe_file(
    sigul_client_config: &Path,
    key: &Key,
    input: &Path,
    output: &Path,
) -> anyhow::Result<()> {
    let passphrase = key.passphrase()?;

    let mut command = tokio::process::Command::new("sigul");
    command
        .args([
            "-v",
            "-v",
            "--batch",
            format!("--config-file={}", sigul_client_config.display()).as_str(),
            "sign-pe",
            "--output",
            output.to_str().unwrap(),
            &key.key_name,
            &key.certificate_name,
            input.to_str().unwrap(),
        ])
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped());
    tracing::debug!(?command, "Issuing signing request via sigul client");
    let mut child = command.spawn()?;
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        if let Some(stdin) = &mut child.stdin {
            stdin.write_all(passphrase.as_bytes()).await?;
            tracing::debug!("Wrote Sigul key passphrase to child's stdin");
        }
        child.wait_with_output().await
    })
    .await??;

    let stderr = String::from_utf8_lossy(&result.stderr);
    let stdout = String::from_utf8_lossy(&result.stdout);
    if result.status.success() {
        tracing::debug!(?command, status=?result.status, ?stderr, ?stdout, "sigul client completed successfully");
        Ok(())
    } else {
        tracing::warn!(?command, status=?result.status, ?stderr, ?stdout, "sigul client failed");
        Err(anyhow!("sigul client failed"))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Once;
    use std::time::Duration;
    use std::{io, num::NonZeroU64};

    use anyhow::{anyhow, Result};
    use bytes::{BufMut, Bytes, BytesMut};
    use nix::sys::stat::Mode;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::sync::CancellationToken;
    use zerocopy::IntoBytes;

    use crate::{config::Config, pesign::Header};

    use super::Command;

    static UMASK: Once = Once::new();

    fn set_umask() {
        UMASK.call_once(|| {
            let mut umask = Mode::empty();
            umask.insert(Mode::S_IRWXO);
            nix::sys::stat::umask(umask);
        });
    }

    // Assert the socket is removed when the service stops
    #[tokio::test]
    async fn socket_is_cleaned_up() -> Result<()> {
        set_umask();
        let socket_dir = tempfile::tempdir()?;
        let socket_path = socket_dir.path().join("socket");
        let config = Config::default();
        let cancel_token = CancellationToken::new();

        let server_task =
            super::listen(socket_dir.path().to_owned(), config, cancel_token.clone())?;

        let _ = std::fs::metadata(&socket_path)?;
        cancel_token.cancel();
        server_task.await??;

        if let Ok(_metadata) = std::fs::metadata(&socket_path) {
            panic!("The socket was not cleaned up!");
        }

        Ok(())
    }

    // Service rejects requests with absurd payload size
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn rejects_large_payloads() -> Result<()> {
        set_umask();
        let socket_dir = tempfile::tempdir()?;
        let socket_path = socket_dir.path().join("socket");
        let config = Config::default();
        let cancel_token = CancellationToken::new();

        let server_task =
            super::listen(socket_dir.path().to_owned(), config, cancel_token.clone())?;
        let client_task = tokio::spawn(async move {
            let mut conn = tokio::net::UnixStream::connect(socket_path).await.unwrap();

            let mut header: Bytes = Header {
                command: Command::GetCmdVersion,
                payload_length: 2048,
            }
            .try_into()
            .unwrap();
            conn.write_all_buf(&mut header).await.unwrap();

            // The server should have hung up on us
            let mut response = [0_u8; 16];
            let result = match conn.read_exact(&mut response).await {
                Ok(_bytes_read) => Err(anyhow!("Server should have hung up")),
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
                Err(error) => Err(anyhow!("Unexpected error: {error:?}")),
            };
            cancel_token.cancel();
            result
        });

        server_task.await??;
        client_task.await??;

        Ok(())
    }

    // Test that the service waits for existing requests to complete (or timeout) after it
    // receives a signal to terminate.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn listen_waits_for_outstanding_tasks() -> Result<()> {
        set_umask();
        let socket_dir = tempfile::tempdir()?;
        let socket_path = socket_dir.path().join("socket");
        let config = Config::default();
        let cancel_token = CancellationToken::new();

        let server_task = super::listen(
            socket_dir.path().to_owned(),
            config.clone(),
            cancel_token.clone(),
        )?;

        let client_task = tokio::spawn(async move {
            let mut conn = tokio::net::UnixStream::connect(&socket_path).await.unwrap();

            cancel_token.cancel();

            // Give the service a fair chance to shut down.
            tokio::time::sleep(Duration::from_millis(5)).await;

            let mut buf = BytesMut::new();
            let header: Bytes = Header {
                command: Command::GetCmdVersion,
                payload_length: std::mem::size_of::<u32>(),
            }
            .try_into()
            .unwrap();
            buf.put_slice(header.as_bytes());
            buf.put_u32_ne(Command::GetCmdVersion.into());
            conn.write_all_buf(&mut buf).await.unwrap();

            let mut response = [0_u8; 16];
            conn.read_exact(&mut response).await.unwrap();

            let mut response = response
                .chunks_exact(4)
                .map(|chunk| chunk.try_into().map(u32::from_ne_bytes));
            let return_code = response.nth(3).unwrap().unwrap();
            assert_eq!(0, return_code);
        });

        server_task.await??;
        client_task.await?;

        assert!(logs_contain(
            "Waiting for pending requests to complete pending_requests=1"
        ));

        Ok(())
    }

    // Test that a request is killed by the server when the configured timeout is hit.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn requests_time_out() -> Result<()> {
        set_umask();
        let socket_dir = tempfile::tempdir()?;
        let socket_path = socket_dir.path().join("socket");
        let config = Config {
            request_timeout_secs: NonZeroU64::new(1).unwrap(),
            ..Default::default()
        };
        let cancel_token = CancellationToken::new();

        let server_task = super::listen(
            socket_dir.path().to_owned(),
            config.clone(),
            cancel_token.clone(),
        )?;

        let client_task = tokio::spawn(async move {
            // Do absolutely nothing at all until the timeout is hit.
            let mut conn = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
            tokio::time::sleep(Duration::from_secs_f64(1.1)).await;

            let mut buf = BytesMut::new();
            let header: Bytes = Header {
                command: Command::GetCmdVersion,
                payload_length: std::mem::size_of::<u32>(),
            }
            .try_into()
            .unwrap();
            buf.put_slice(header.as_bytes());
            buf.put_u32_ne(Command::GetCmdVersion.into());
            if conn.write_all_buf(&mut buf).await.is_ok() {
                panic!("The server should have hung up on us.")
            }
            cancel_token.cancel();
        });

        server_task.await??;
        client_task.await?;

        assert!(logs_contain("Request handler timed out!"));

        Ok(())
    }
}
