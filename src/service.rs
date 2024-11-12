// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::{
    ffi::CStr,
    fs::File,
    io::{self, IoSliceMut, Read, Write},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, RawFd},
        unix::fs::PermissionsExt,
    },
    path::PathBuf,
    time::Duration,
};

use anyhow::{anyhow, Context};
use bytes::BufMut;
use nix::{
    cmsg_space,
    sys::{
        socket::{MsgFlags, UnixAddr},
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

/// The version of the pesign daemon interface we support.
///
/// The pesign-client will reject a version mis-match so if
/// pesign adjusts the version we will stop working with it.
/// However, as we'll likely add our own interface later this
/// shouldn't be an issue. Probably.
const PESIGND_VERSION: u32 = 0x2a9edaf0;

const CMD_KILL_DAEMON: u32 = 0;
const CMD_UNLOCK_TOKEN: u32 = 1;
const CMD_SIGN_ATTACHED: u32 = 2;
const CMD_SIGN_DETACHED: u32 = 3;
const CMD_RESPONSE: u32 = 4;
const CMD_IS_TOKEN_UNLOCKED: u32 = 5;
const CMD_GET_CMD_VERSION: u32 = 6;
const CMD_SIGN_ATTACHED_WITH_FILE_TYPE: u32 = 7;
const CMD_SIGN_DETACHED_WITH_FILE_TYPE: u32 = 8;

const PESIGN_HEADER_SIZE: usize = std::mem::size_of::<u32>() * 3;
const PESIGN_MAX_PAYLOAD: usize = 1024;

/// Describes the pesign request/response.
///
/// Each client request and server response starts with this header.
/// These requests are sent over a Unix socket and use native endian
/// byte order.
#[derive(Debug, Copy, Clone)]
struct Header {
    command: Command,
    payload_length: usize,
}

impl TryFrom<[u8; PESIGN_HEADER_SIZE]> for Header {
    type Error = anyhow::Error;

    fn try_from(value: [u8; PESIGN_HEADER_SIZE]) -> Result<Self, Self::Error> {
        let mut header = value
            .chunks_exact(std::mem::size_of::<u32>())
            .map(|chunk| chunk.try_into().map(u32::from_ne_bytes));

        let pesign_version = header
            .next()
            .ok_or_else(|| anyhow!("Programmer error: the header should be of length 3"))??;

        if pesign_version != PESIGND_VERSION {
            return Err(anyhow!(
                "Unsupported version of pesign (expected {}, got {})",
                PESIGND_VERSION,
                pesign_version
            ));
        }

        let command: Command = header
            .next()
            .ok_or_else(|| anyhow!("Programmer error: the header should be of length 3"))??
            .try_into()?;

        let payload_length: usize = header
            .next()
            .ok_or_else(|| anyhow!("Programmer error: the header should be of length 3"))??
            .try_into()?;

        if payload_length > PESIGN_MAX_PAYLOAD {
            return Err(anyhow!("Client declared absurd payload size"));
        }

        Ok(Self {
            command,
            payload_length,
        })
    }
}

#[derive(Debug, Copy, Clone)]
enum Command {
    Kill,
    UnlockToken,
    SignAttached,
    SignDetached,
    Response,
    IsTokenUnlocked,
    GetCmdVersion,
    SignAttachedWithFileType,
    SignDetachedWithFileType,
}

impl TryFrom<u32> for Command {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            CMD_KILL_DAEMON => Ok(Self::Kill),
            CMD_UNLOCK_TOKEN => Ok(Self::UnlockToken),
            CMD_SIGN_ATTACHED => Ok(Self::SignAttached),
            CMD_SIGN_DETACHED => Ok(Self::SignDetached),
            CMD_RESPONSE => Ok(Self::Response),
            CMD_IS_TOKEN_UNLOCKED => Ok(Self::IsTokenUnlocked),
            CMD_GET_CMD_VERSION => Ok(Self::GetCmdVersion),
            CMD_SIGN_ATTACHED_WITH_FILE_TYPE => Ok(Self::SignAttachedWithFileType),
            CMD_SIGN_DETACHED_WITH_FILE_TYPE => Ok(Self::SignDetachedWithFileType),
            _ => Err(anyhow!("Unknown Command '{}'", value)),
        }
    }
}

#[instrument(err, skip_all)]
pub(crate) fn listen(
    path: PathBuf,
    halt_token: CancellationToken,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    let listener = UnixListener::bind(&path)
        .with_context(|| format!("Failed to bind to {}", &path.display()))?;
    let metadata = std::fs::metadata(&path)?;
    if metadata.permissions().mode() & Mode::S_IRWXO.bits() != 0 {
        return Err(anyhow!(
            "Other users have access to the socket, adjust the service umask!"
        ));
    }
    tracing::info!(socket=?path, "Listening");

    let request_tracker = TaskTracker::new();

    Ok(tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = halt_token.cancelled() => {
                    tracing::info!(socket=?path, "Shutdown requested, no new requests will be accepted");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((unix_stream, _)) => {
                            request_tracker.spawn(request(unix_stream).instrument(tracing::Span::current()));
                        },
                        Err(error) => {
                            tracing::error!(socket=?path, ?error, "Failed to accept request");
                        },
                    }
                }
            }
        }

        // Remove the socket and then wait for any requests in progress to complete before
        // exiting.
        std::fs::remove_file(&path)
            .with_context(|| format!("Failed to remove socket {}", &path.display()))?;
        tracing::debug!(socket=?path, "Successfully removed socket");
        tracing::info!(
            pending_requests = request_tracker.len(),
            "Waiting for pending requests to complete"
        );
        request_tracker.close();
        request_tracker.wait().await;

        Ok(())
    }.instrument(tracing::Span::current())))
}

#[instrument(skip_all, ret, fields(request_id = uuid::Uuid::now_v7().to_string()))]
async fn request(unix_stream: UnixStream) -> Result<(), anyhow::Error> {
    // TODO: This is obviously not long enough for a signing request; make it configurable
    // or extremely long.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        request_handler(unix_stream),
    )
    .await;
    if result.is_err() {
        tracing::error!("Request handler timed out!");
    }

    result?
}

async fn request_handler(mut unix_stream: UnixStream) -> Result<(), anyhow::Error> {
    loop {
        // Read the command header, which gives us the requested command and payload size.
        let mut buf = [0_u8; PESIGN_HEADER_SIZE];
        match unix_stream.read_exact(&mut buf).await {
            Ok(_bytes_read) => {
                let request: Header = buf.try_into()?;
                tracing::debug!(?request, "Client request received");

                match request.command {
                    Command::IsTokenUnlocked => {
                        is_token_unlocked(&mut unix_stream, request.payload_length).await
                    }
                    Command::GetCmdVersion => {
                        get_command_version(&mut unix_stream, request.payload_length).await
                    }
                    Command::SignAttachedWithFileType => {
                        sign_attached_with_filetype(&mut unix_stream, request.payload_length).await
                    }
                    Command::SignAttached => {
                        // TODO: Once we parse the filetype and stuff out of the request we need to
                        // split this up from the _with_filetype
                        sign_attached_with_filetype(&mut unix_stream, request.payload_length).await
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
    // Send pesignd_msghdr (version, CMD_REPONSE, size) + pesignd_cmd_response (return_code i32, [u8] errmsg), command version always 0
    let mut buf = bytes::BytesMut::new();
    buf.put_u32_ne(PESIGND_VERSION);
    buf.put_u32_ne(CMD_RESPONSE);
    // Payload size (one i32, plus an optional null-terminated string of u8s)
    // Since we never return an error string, the payload is always the size of an i32
    buf.put_u32_ne(4_u32);

    match Command::try_from(command) {
        Ok(
            Command::GetCmdVersion
            | Command::IsTokenUnlocked
            | Command::SignAttachedWithFileType
            | Command::SignAttached,
        ) => {
            tracing::debug!(
                "Client queried for the server version of command {:?}",
                command
            );
            buf.put_i32_ne(0_i32);
            connection.write_all_buf(&mut buf).await?;
            Ok(())
        }
        Ok(command) => {
            tracing::warn!(
                "Client queried for the server version of command {:?}, which is not supported",
                command
            );
            buf.put_i32_ne(-1_i32);
            connection.write_all_buf(&mut buf).await?;
            Ok(())
        }
        Err(error) => {
            tracing::error!(
                error = ?error,
                command = "get-cmd-version",
                queried_command = command,
                "Unknown command version requested"
            );
            buf.put_i32_ne(-1_i32);
            connection.write_all_buf(&mut buf).await?;
            return Err(anyhow!("get-cmd-version request was malformed"));
        }
    }
}

#[instrument(skip_all, ret, fields(token = tracing::field::Empty))]
async fn is_token_unlocked(
    connection: &mut UnixStream,
    payload_length: usize,
) -> Result<(), anyhow::Error> {
    // The expected payload is a u32 which is the length of the C-style string
    // which follows it.
    if std::mem::size_of::<u32>() > payload_length {
        return Err(anyhow!(
            "Client payload for is-token-unlocked is too small!"
        ));
    }
    let mut payload = vec![0_u8; payload_length];
    connection.read_exact(&mut payload).await?;

    let (token_name_len, token_name) = payload.split_at(std::mem::size_of::<u32>());
    let token_name_len: usize = token_name_len
        .try_into()
        .map(u32::from_ne_bytes)?
        .try_into()?;
    if token_name.len() != token_name_len {
        tracing::error!(
            name_length = token_name_len,
            payload_size = token_name.len(),
            "Token name length doesn't match the payload size"
        );
        return Err(anyhow!(
            "Client sent malformed request for is-token-unlocked"
        ));
    }

    let token_name = CStr::from_bytes_until_nul(token_name)?.to_str()?;
    tracing::Span::current().record("token", token_name);

    // Lie and always say the token is unlocked for now
    let mut buf = bytes::BytesMut::new();
    buf.put_u32_ne(PESIGND_VERSION);
    buf.put_u32_ne(CMD_RESPONSE);
    buf.put_u32_ne(4_u32);
    buf.put_i32_ne(0_i32);
    connection.write_all_buf(&mut buf).await?;

    Ok(())
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
#[instrument(skip_all, ret)]
async fn sign_attached_with_filetype(
    connection: &mut UnixStream,
    payload_length: usize,
) -> Result<(), anyhow::Error> {
    // TODO: needs lots of tidying
    let mut payload = vec![0_u8; payload_length];
    connection.read_exact(&mut payload).await?;
    tracing::trace!(?payload_length, ?payload, "Read payload");

    let raw_fd = connection.as_fd().as_raw_fd();
    // Both the Rust standard library and tokio don't include support for ancillary data
    // over Unix sockets. Instead, we use the nix library's blocking interface to retrieve
    // the file descriptors from the client.
    //
    // https://github.com/rust-lang/rust/issues/76915
    let cmsgs = tokio::task::spawn_blocking(move || {
        let mut cmsgs = vec![];
        let mut iovs = vec![];

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
            tracing::info!(
                ?cmsg,
                "Read control message from client with file descriptor"
            );
            cmsgs.append(&mut cmsg);

            // TODO: Drop or log if we read something unexpected, these should all be null bytes.
            let mut iov = result.iovs().map(|buf| buf.to_vec()).collect::<Vec<_>>();
            tracing::info!(?iov, "Read iov from client with file descriptor");
            iovs.append(&mut iov);
        }

        Ok(cmsgs)
    })
    .await??;

    let mut files = vec![];
    for cmsg in cmsgs {
        match cmsg {
            nix::sys::socket::ControlMessageOwned::ScmRights(fds) => {
                if fds.len() != 1 {
                    return Err(anyhow!("Unexpected number of file descriptors sent"));
                }

                // TODO: Maybe tokio files?
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

    let [mut input_file, mut output_file]: [File; 2] = files
        .try_into()
        .map_err(|error| anyhow!("Client did not send the expected number of files: {error:?}"))?;

    let mut in_file_text = String::new();
    let in_file_size = input_file.read_to_string(&mut in_file_text).ok();
    tracing::info!(?in_file_size, ?in_file_text, "read from fd");
    in_file_text += "\nSigned, Jeremy\n";
    output_file.write_all(in_file_text.as_bytes())?;
    drop(input_file);
    drop(output_file);

    // TODO: If we fail to sign the binary, we need to respond with an error to the client
    let mut buf = bytes::BytesMut::new();
    buf.put_u32_ne(PESIGND_VERSION);
    buf.put_u32_ne(CMD_RESPONSE);
    buf.put_u32_ne(4_u32);
    buf.put_i32_ne(0_i32);
    connection.write_all_buf(&mut buf).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Once;
    use std::time::Duration;

    use anyhow::{anyhow, Result};
    use bytes::{BufMut, BytesMut};
    use nix::sys::stat::Mode;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::sync::CancellationToken;

    use super::{CMD_GET_CMD_VERSION, PESIGND_VERSION};

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
        let cancel_token = CancellationToken::new();

        let server_task = super::listen(socket_path.clone(), cancel_token.clone())?;

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
        let cancel_token = CancellationToken::new();

        let server_task = super::listen(socket_path.clone(), cancel_token.clone())?;
        let client_task = tokio::spawn(async move {
            let mut conn = tokio::net::UnixStream::connect(&socket_path).await.unwrap();

            let mut buf = BytesMut::new();
            buf.put_u32_ne(PESIGND_VERSION);
            buf.put_u32_ne(CMD_GET_CMD_VERSION);
            buf.put_u32_ne(2048);
            conn.write_all_buf(&mut buf).await.unwrap();

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
        let cancel_token = CancellationToken::new();

        let server_task = super::listen(socket_path.clone(), cancel_token.clone())?;

        let client_task = tokio::spawn(async move {
            let mut conn = tokio::net::UnixStream::connect(&socket_path).await.unwrap();

            cancel_token.cancel();

            // Give the service a fair chance to shut down.
            tokio::time::sleep(Duration::from_millis(5)).await;

            let mut buf = BytesMut::new();
            buf.put_u32_ne(PESIGND_VERSION);
            buf.put_u32_ne(CMD_GET_CMD_VERSION);
            buf.put_u32_ne(4);
            buf.put_u32_ne(CMD_GET_CMD_VERSION);
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
}
