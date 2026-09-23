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

use std::{
    num::NonZeroU32,
    os::fd::{AsFd, FromRawFd, OwnedFd},
};

use anyhow::Context;
use openssl::hash::{Hasher, MessageDigest};
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;

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

/// Calculate the mu value for ML-DSA signatures.
#[doc(hidden)]
pub fn calculate_mu<'a, P: openssl::pkey::HasPublic + 'a>(
    public_key: impl Into<&'a openssl::pkey::PKey<P>>,
    message: &[u8],
    context: Option<&[u8]>,
) -> Result<[u8; 64], anyhow::Error> {
    let mut hasher = begin_mu(public_key, context)?;
    hasher.update(message)?;
    let mut mu_digest = [0_u8; 64];
    hasher.finish_xof(&mut mu_digest)?;

    Ok(mu_digest)
}

/// Prepare a Hasher for calculating Mu.
///
/// The hasher returned has been fed:
///
/// SHAKE256(public_key, 64) || 0x00 || context_len || context
///
/// All that remains to calculate Mu is to update the hasher with the message and call
/// `finish_xof()` with a 64 byte target buffer.
#[doc(hidden)]
pub fn begin_mu<'a, P: openssl::pkey::HasPublic + 'a>(
    public_key: impl Into<&'a openssl::pkey::PKey<P>>,
    context: Option<&[u8]>,
) -> Result<Hasher, anyhow::Error> {
    // Prepare the hash object with the 64-byte SHAKE256 hash of the public key, a null byte,
    // the length of the context as a single byte, and then the context (maximum of 255 bytes).
    let mut pubkey_hash = [0_u8; 64];
    openssl::hash::hash_xof(
        MessageDigest::shake_256(),
        public_key.into().raw_public_key()?.as_slice(),
        &mut pubkey_hash,
    )?;
    let mut hasher = Hasher::new(MessageDigest::shake_256())?;
    hasher.update(&pubkey_hash)?;
    hasher.update(&[0_u8])?;

    let context = context.unwrap_or_default();
    let context_len =
        u8::try_from(context.len()).context("ML-DSA context must not exceed 255 bytes")?;
    hasher.update(&[context_len])?;
    hasher.update(context)?;

    Ok(hasher)
}

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

/// Set the process's open file limit to the maximum allowable.
///
/// The default soft limit is 1024 to protect programs that use syscalls that cannot
/// operate on fd > 1024; we don't so we can opt out and use the real system limits.
#[cfg(feature = "cli")]
#[doc(hidden)]
pub fn raise_nofiles() -> anyhow::Result<()> {
    use anyhow::Context;

    let current_nofile_limits = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    let mut new_nofile_limits = current_nofile_limits;
    new_nofile_limits.current = current_nofile_limits.maximum;
    tracing::debug!(
        "Raising the RLIMIT_NOFILE value from {:?} to {:?}",
        current_nofile_limits.current,
        new_nofile_limits.current
    );
    rustix::process::setrlimit(rustix::process::Resource::Nofile, new_nofile_limits)
        .context("Failed to set file limits")?;

    Ok(())
}

/// Check for and return any file descriptors passed in from systemd
///
/// Refer to sd_listen_fds (3) for details.
///
/// Returns the list of (optional) file descriptor name and the descriptor itself.
#[doc(hidden)]
#[cfg(feature = "cli")]
pub fn listen_fds() -> Result<Vec<(Option<String>, OwnedFd)>, anyhow::Error> {
    const SD_LISTEN_FDS_START: u32 = 3;
    const PID_FS_MAGIC: u64 = 0x50494446;

    let our_pid = std::process::id();

    match std::env::var("LISTEN_PID") {
        Ok(listen_pid) => {
            let listen_pid = listen_pid.parse::<u32>().with_context(|| {
                format!("Failed to parse LISTEN_PID={listen_pid} as an unsigned 32 bit integer")
            })?;
            if our_pid != listen_pid {
                tracing::warn!(listen_pid, our_pid, "LISTEN_PID provided, but not for us");
                return Ok(vec![]);
            }
        }
        Err(_) => return Ok(vec![]),
    }

    // Newer systemd versions will also provide the pidfd's inode so we can double check
    // these variables really are meant for us.
    if let Ok(listen_pidfdid) = std::env::var("LISTEN_PIDFDID") {
        let listen_pidfdid = listen_pidfdid.parse::<u64>().with_context(|| {
            format!("Failed to parse LISTEN_PIDFDID={listen_pidfdid} as an unsigned 64 bit integer")
        })?;
        tracing::debug!("systemd provided LISTEN_PIDFDID={listen_pidfdid}");

        let pidfd = rustix::process::pidfd_open(
            rustix::process::getpid(),
            rustix::process::PidfdFlags::empty(),
        )
        .context("Failed to open a pidfd for our own process")?;
        if rustix::fs::fstatfs(&pidfd)
            .map(|statfs| {
                tracing::debug!(statfs.f_type, "PIDFD filesystem type");
                statfs.f_type as u64 == PID_FS_MAGIC
            })
            .inspect_err(|error| {
                tracing::info!(
                    ?error,
                    "Failed to read PIDFD's filesystem statistics, skipping LISTEN_PIDFDID check"
                );
            })
            .unwrap_or(false)
        {
            let our_pidfdid = rustix::fs::fstat(&pidfd)
                .context("Failed to stat our pidfd")?
                .st_ino;
            if our_pidfdid != listen_pidfdid {
                tracing::warn!(
                    listen_pidfdid,
                    our_pidfdid,
                    "LISTEN_PIDFDID provided, but not for us"
                );
                return Ok(vec![]);
            } else {
                tracing::debug!(our_pidfdid, "LISTEN_PIDFDID matches our pidfd ID");
            }
        }
    }

    let mut fds = vec![];
    let fd_names = std::env::var("LISTEN_FDNAMES")
        .map(|names| names.split(":").map(|n| n.to_string()).collect::<Vec<_>>())
        .inspect_err(|_| tracing::debug!("No LISTEN_FDNAMES variable provided"))
        .unwrap_or_default();
    if let Ok(num) = std::env::var("LISTEN_FDS") {
        let fd_count = num.parse::<NonZeroU32>().with_context(|| {
            format!("Failed to parse LISTEN_FDS={num} as a non-zero unsigned integer")
        })?;
        if fd_count.get() > u32::MAX - SD_LISTEN_FDS_START {
            return Err(anyhow::anyhow!(
                "Number of file descriptors provided would overflow a u32"
            ));
        }

        let mut names = fd_names.into_iter();
        for fd in SD_LISTEN_FDS_START..SD_LISTEN_FDS_START + fd_count.get() {
            let raw_fd = fd.try_into().with_context(|| {
                format!("Failed to convert the file descriptor {fd} to a RawFd")
            })?;

            // Safety:
            //
            // systemd promises that if it sets the LISTEN_FDS environment variable to a non-zero
            // number, it shall provide that number of valid file descriptors to the program it
            // executes. Furthermore, these file descriptors are guaranteed to start at 3 (e.g.
            // directly after the stdin, stdout, and stderr descriptors) and continue up to the
            // value provided in LISTEN_FDS + 3.
            let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

            let old_flags =
                rustix::io::fcntl_getfd(owned_fd.as_fd()).context("Failed to retrieve fd flags")?;
            let mut new_flags = old_flags;
            new_flags.insert(rustix::io::FdFlags::CLOEXEC);
            tracing::debug!(?old_flags, ?new_flags, "Setting CLOEXEC on fd");
            rustix::io::fcntl_setfd(owned_fd.as_fd(), new_flags)
                .context("Failed to set CLOEXEC")?;
            fds.push((names.next(), owned_fd));
        }
    }

    Ok(fds)
}

#[cfg(test)]
mod tests {
    use openssl::pkey::PKey;

    use super::*;

    #[test]
    fn mu_includes_context() -> anyhow::Result<()> {
        let mut seed = [0_u8; 32];
        openssl::rand::rand_priv_bytes(&mut seed)?;
        let private_key =
            PKey::private_key_from_seed(None, openssl::pkey::KeyType::ML_DSA_65, None, &seed)?;
        let message = b"beep boop";
        let context = b"namespace this signature";

        let actual = calculate_mu(&private_key, message, Some(context))?;
        let actual_no_context = calculate_mu(&private_key, message, None)?;

        assert_ne!(actual, actual_no_context);

        let mut public_key_hash = [0_u8; 64];
        openssl::hash::hash_xof(
            MessageDigest::shake_256(),
            private_key.raw_public_key()?.as_slice(),
            &mut public_key_hash,
        )?;
        let mut expected_input = public_key_hash.to_vec();
        expected_input.extend_from_slice(&[0, context.len() as u8]);
        expected_input.extend_from_slice(context);
        expected_input.extend_from_slice(message);
        let mut expected = [0_u8; 64];
        openssl::hash::hash_xof(MessageDigest::shake_256(), &expected_input, &mut expected)?;

        assert_eq!(actual, expected);
        Ok(())
    }

    #[test]
    fn mu_context_is_limited_to_255_bytes() -> anyhow::Result<()> {
        let mut seed = [0_u8; 32];
        openssl::rand::rand_priv_bytes(&mut seed)?;
        let private_key =
            PKey::private_key_from_seed(None, openssl::pkey::KeyType::ML_DSA_65, None, &seed)?;
        let public_key = PKey::public_key_from_pem(&private_key.public_key_to_pem()?)?;

        begin_mu(&private_key, Some(&[0_u8; 255]))?;
        let error = begin_mu(&public_key, Some(&[0_u8; 256]))
            .err()
            .expect("a 256-byte context should be rejected");

        assert_eq!(
            error.to_string(),
            "ML-DSA context must not exceed 255 bytes"
        );
        Ok(())
    }
}
