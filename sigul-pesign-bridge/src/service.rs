// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::{
    env,
    ffi::CStr,
    fs::File,
    io::{self, IoSliceMut},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, RawFd},
        unix::fs::PermissionsExt,
    },
    path::Path,
    process::Stdio,
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

use crate::config::{Config, Key};

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

impl TryFrom<&[u8]> for Header {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != PESIGN_HEADER_SIZE {
            return Err(anyhow!("Invalid header size"));
        }

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

#[derive(Clone, Debug, Default, PartialEq)]
struct SignAttachedRequest {
    token_name: String,
    certificate_name: String,
}

impl TryFrom<&[u8]> for SignAttachedRequest {
    type Error = anyhow::Error;

    /// Attempt to parse the request from the payload bytes.
    ///
    /// A valid request is composed of:
    ///
    /// 1. FILE_TYPE (u32) - The file type.
    /// 2. TOKEN_LEN (u32) - The length of the token name string.
    /// 3. TOKEN_NAME ([u8; TOKEN_LEN]) - A null-terminated string identifying the token
    ///    to use when signing.
    /// 4. CERT_LEN (u32) - The length of the certificate name string.
    /// 5. CERT_NAME ([u8; CERT_LEN]) - A null-terminated string identifying the certificate
    ///    to use when signing.
    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        if payload.len() < std::mem::size_of::<u32>() * 3 {
            return Err(anyhow!("Request payload is too small"));
        }

        // pesign also defines a type for kernel modules, but at the moment we don't do anything for those.
        let (file_type, remaining_payload) = payload.split_at(std::mem::size_of::<u32>());
        let file_type = file_type.try_into().map(u32::from_ne_bytes)?;
        if file_type != 0 {
            return Err(anyhow!("Unsupported file type; only PE type supported"));
        }

        let (token_length, remaining_payload) =
            remaining_payload.split_at(std::mem::size_of::<u32>());
        let token_length: usize = token_length
            .try_into()
            .map(u32::from_ne_bytes)?
            .try_into()?;
        if token_length > remaining_payload.len() {
            return Err(anyhow!(
                "Malformed request; token length longer than payload"
            ));
        }
        let (token_name, remaining_payload) = remaining_payload.split_at(token_length);
        let token = CStr::from_bytes_until_nul(token_name)?
            .to_str()?
            .to_string();

        let (cert_length, remaining_payload) =
            remaining_payload.split_at(std::mem::size_of::<u32>());
        let cert_length: usize = cert_length.try_into().map(u32::from_ne_bytes)?.try_into()?;
        if cert_length != remaining_payload.len() {
            return Err(anyhow!(
                "Malformed request; certificate name length doesn't match payload size"
            ));
        }
        let certificate = CStr::from_bytes_until_nul(remaining_payload)?
            .to_str()?
            .to_string();

        Ok(Self {
            token_name: token,
            certificate_name: certificate,
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

/// Listen on a Unix socket on the given path.
///
/// This function will bind the socket and check its permissions,
/// then spawn an asynchronous worker to handle requests. To stop
/// the worker, cancel the given `halt_token` and then await the
/// returned [`JoinHandle`].
///
/// Pending requests will be allowed to complete before the task
/// completes.
#[instrument(err, skip_all)]
pub(crate) fn listen(
    config: Config,
    halt_token: CancellationToken,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    let listener = UnixListener::bind(&config.socket_path)
        .with_context(|| format!("Failed to bind to {}", &config.socket_path.display()))?;
    let metadata = std::fs::metadata(&config.socket_path)?;
    if metadata.permissions().mode() & Mode::S_IRWXO.bits() != 0 {
        tracing::error!(mode=?metadata.permissions(), "Service socket has dangerous permissions!");
        std::fs::remove_file(&config.socket_path).with_context(|| {
            format!("Failed to remove socket {}", &config.socket_path.display())
        })?;
        return Err(anyhow!(
            "Other users have access to the socket, adjust the service umask!"
        ));
    }
    tracing::info!(socket=?config.socket_path, "Listening");

    let request_tracker = TaskTracker::new();

    Ok(tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = halt_token.cancelled() => {
                    tracing::info!(socket=?config.socket_path, "Shutdown requested, no new requests will be accepted");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((unix_stream, _)) => {
                            request_tracker.spawn(request(config.clone(), unix_stream).instrument(tracing::Span::current()));
                        },
                        Err(error) => {
                            tracing::error!(socket=?config.socket_path, ?error, "Failed to accept request");
                        },
                    }
                }
            }
        }

        // Remove the socket and then wait for any requests in progress to complete before
        // exiting.
        std::fs::remove_file(&config.socket_path)
            .with_context(|| format!("Failed to remove socket {}", &config.socket_path.display()))?;
        tracing::debug!(socket=?config.socket_path, "Successfully removed socket");
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
async fn request(config: Config, unix_stream: UnixStream) -> Result<(), anyhow::Error> {
    let result = tokio::time::timeout(
        Duration::from_secs(config.request_timeout_secs.get()),
        request_handler(config, unix_stream),
    )
    .await;
    if result.is_err() {
        tracing::error!("Request handler timed out!");
    }

    result?
}

async fn request_handler(config: Config, mut unix_stream: UnixStream) -> Result<(), anyhow::Error> {
    loop {
        // Read the command header, which gives us the requested command and payload size.
        let mut buf = [0_u8; PESIGN_HEADER_SIZE];
        match unix_stream.read_exact(&mut buf).await {
            Ok(_bytes_read) => {
                let request: Header = buf.as_slice().try_into()?;
                tracing::debug!(?request, "Client request received");

                match request.command {
                    Command::GetCmdVersion => {
                        get_command_version(&mut unix_stream, request.payload_length).await
                    }
                    Command::SignAttachedWithFileType => {
                        sign_attached_with_filetype(
                            &config,
                            &mut unix_stream,
                            request.payload_length,
                        )
                        .await
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
        Ok(Command::GetCmdVersion | Command::SignAttachedWithFileType) => {
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
    config: &Config,
    connection: &mut UnixStream,
    payload_length: usize,
) -> Result<(), anyhow::Error> {
    // TODO: needs lots of tidying
    let mut payload = vec![0_u8; payload_length];
    connection.read_exact(&mut payload).await?;
    tracing::trace!(?payload_length, ?payload, "Read payload");

    let request = SignAttachedRequest::try_from(payload.as_slice())?;
    tracing::info!(?request.token_name, ?request.certificate_name, "Client signing request received");

    let key = config
        .keys
        .iter()
        .find(|key| {
            key.key_name == request.token_name && key.certificate_name == request.certificate_name
        })
        .ok_or_else(|| {
            tracing::error!(
                ?request,
                "Configuration does not have the requested key/cert pair"
            );
            anyhow!("Client requested a token and certificate name we don't know about!")
        })?;

    // Both the Rust standard library and tokio don't include support for ancillary data
    // over Unix sockets. Instead, we use the nix library's blocking interface to retrieve
    // the file descriptors from the client.
    //
    // https://github.com/rust-lang/rust/issues/76915
    let raw_fd = connection.as_fd().as_raw_fd();
    let span = tracing::Span::current();
    let cmsgs = tokio::task::spawn_blocking(move || {
        let _enter = span.enter();
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
            tracing::info!(
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

    let [mut pe_client_input_file, mut pe_client_output_file]: [File; 2] = files
        .try_into()
        .map_err(|error| anyhow!("Client did not send the expected number of files: {error:?}"))?;

    let runtime_directory = env::var("RUNTIME_DIRECTORY").unwrap_or_else(|error| {
        tracing::warn!(?error, "Failed to read RUNTIME_DIRECTORY environment variable, falling back to /run/sigul-pesign-bridge/");
        "/run/sigul-pesign-bridge/".into()
    });
    let temp_dir = tempfile::Builder::new()
        .prefix(".work")
        .rand_bytes(16)
        .tempdir_in(&runtime_directory)
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
        let input_bytes = std::io::copy(&mut pe_client_input_file, &mut sigul_input_file).inspect_err(|error| {
            tracing::error!(?error, path=?sigul_input, "Failed to copy the input file to a temporary file for sigul input")
        })?;
        tracing::info!(input_bytes, "Forwarding PE file to Sigul for signing");

        Ok::<_, anyhow::Error>(sigul_input)
    }).await??;

    // TODO Might want to come up with a more elegant retry since this relies on the request timeout
    // and then we never respond to the client.
    let sigul_client_config = config.sigul_client_config()?;
    while let Err(error) =
        forward_pe_file(&sigul_client_config, key, &sigul_input, &sigul_output).await
    {
        tracing::warn!(%error, "signing failed; retrying sigul client in 2 seconds");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    // TODO validate signed PE with the configured certificate here

    let span = tracing::Span::current();
    tokio::task::spawn_blocking(move || {
        let _enter = span.enter();
        let mut sigul_output_file = std::fs::File::options().create(false).read(true).open(&sigul_output).inspect_err(|error| {
            tracing::error!(?error, path=?sigul_output, "Failed to open the temporary file used for sigul output");
        })?;
        let output_bytes = std::io::copy(&mut sigul_output_file, &mut pe_client_output_file).inspect_err(|error| {
            tracing::error!(?error, path=?sigul_input, "Failed to copy the input file to a temporary file for sigul input")
        })?;
        tracing::info!(output_bytes, "Signing request completed");
        Ok::<_, anyhow::Error>(())
    }).in_current_span().await??;

    // TODO: If we fail to sign the binary, we need to respond with an error to the client
    let mut buf = bytes::BytesMut::new();
    buf.put_u32_ne(PESIGND_VERSION);
    buf.put_u32_ne(CMD_RESPONSE);
    buf.put_u32_ne(4_u32);
    buf.put_i32_ne(0_i32);
    connection.write_all_buf(&mut buf).await?;

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
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped());
    tracing::debug!(?command, "Issuing signing request via sigul client");
    let mut child = command.spawn()?;
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        if let Some(stdin) = &mut child.stdin {
            stdin.write_all(passphrase.as_bytes()).await?;
            tracing::debug!("Wrote password to stdin");
        }
        tracing::debug!("Waiting on child to complete");
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
    use std::io;
    use std::sync::Once;
    use std::time::Duration;

    use anyhow::{anyhow, Result};
    use bytes::{BufMut, BytesMut};
    use nix::sys::stat::Mode;
    use proptest::prelude::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::sync::CancellationToken;

    use crate::config::Config;

    use super::{
        Header, SignAttachedRequest, CMD_GET_CMD_VERSION, PESIGND_VERSION, PESIGN_MAX_PAYLOAD,
    };

    static UMASK: Once = Once::new();

    fn set_umask() {
        UMASK.call_once(|| {
            let mut umask = Mode::empty();
            umask.insert(Mode::S_IRWXO);
            nix::sys::stat::umask(umask);
        });
    }

    proptest! {
        // Regardless of header correctness, it should never crash.
        #[test]
        fn header_never_panics(payload in prop::array::uniform12(u8::MIN..u8::MAX)) {
            let _ = Header::try_from(payload.as_slice());
        }

        #[test]
        fn header_valid_commands(mut payload in vec![0..8u32, 0..1024u32]) {
            payload.insert(0, PESIGND_VERSION);
            let payload = payload.into_iter().flat_map(|b| b.to_ne_bytes()).collect::<Vec<_>>();
            Header::try_from(payload.as_slice()).unwrap();
        }

        #[test]
        fn header_invalid_commands(mut payload in vec![8..u32::MAX, 0..1024u32]) {
            payload.insert(0, PESIGND_VERSION);
            let payload = payload.into_iter().flat_map(|b| b.to_ne_bytes()).collect::<Vec<_>>();
            if Header::try_from(payload.as_slice()).is_ok() {
                panic!("Header shouldn't contain a command over 8");
            }
        }

        #[test]
        fn header_payload_size(payload_size in 0..1024u32) {
            let payload = vec![PESIGND_VERSION, 8, payload_size];
            let payload = payload.into_iter().flat_map(|b| b.to_ne_bytes()).collect::<Vec<_>>();
            let result = Header::try_from(payload.as_slice());
            if payload_size > PESIGN_MAX_PAYLOAD as u32 {
                if result.is_ok() {
                    panic!("Payload was too large");
                }
            } else {
                result.unwrap();
            }
        }

        // Regardless of payload correctness, it should never crash.
        #[test]
        fn sign_attached_request_never_panics(payload in prop::collection::vec(u8::MIN..u8::MAX, 0..PESIGN_MAX_PAYLOAD)) {
            let _ = SignAttachedRequest::try_from(payload.as_slice());
        }

        // Generate some acceptable requests using random token and certificate names
        #[test]
        fn sign_attached_request(name in "\\PC+") {
            let mut payload = Vec::from(0_u32.to_ne_bytes());
            let name_bytes = name.as_bytes();
            for _ in 0..2 {
                payload.extend_from_slice((name_bytes.len() as u32 + 1).to_ne_bytes().as_slice());
                payload.extend_from_slice(name_bytes);
                payload.push(0);
            }

            SignAttachedRequest::try_from(payload.as_slice()).unwrap();
        }

    }

    // Assert the socket is removed when the service stops
    #[tokio::test]
    async fn socket_is_cleaned_up() -> Result<()> {
        set_umask();
        let socket_dir = tempfile::tempdir()?;
        let config = Config {
            socket_path: socket_dir.path().join("socket"),
            ..Default::default()
        };
        let cancel_token = CancellationToken::new();

        let server_task = super::listen(config.clone(), cancel_token.clone())?;

        let _ = std::fs::metadata(&config.socket_path)?;
        cancel_token.cancel();
        server_task.await??;

        if let Ok(_metadata) = std::fs::metadata(&config.socket_path) {
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
        let config = Config {
            socket_path: socket_dir.path().join("socket"),
            ..Default::default()
        };
        let cancel_token = CancellationToken::new();

        let server_task = super::listen(config.clone(), cancel_token.clone())?;
        let client_task = tokio::spawn(async move {
            let mut conn = tokio::net::UnixStream::connect(&config.socket_path)
                .await
                .unwrap();

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
        let config = Config {
            socket_path: socket_dir.path().join("socket"),
            ..Default::default()
        };
        let cancel_token = CancellationToken::new();

        let server_task = super::listen(config.clone(), cancel_token.clone())?;

        let client_task = tokio::spawn(async move {
            let mut conn = tokio::net::UnixStream::connect(&config.socket_path)
                .await
                .unwrap();

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
