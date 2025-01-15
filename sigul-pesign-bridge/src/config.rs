// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! The configuration format for `sigul-pesign-bridge`.
//!
//! Configuration is provided via a command-line argument or environment
//! variable (`SIGUL_PESIGN_BRIDGE_CONFIG`). The configuration should be in TOML format.
//!
//! The [`Config`] has several top-level settings, as well as a list of one or
//! more signing [`Key`] settings.
//!
//! There is no configuration merging: a configuration file must contain
//! settings for _all_ required fields.
//!
//! To validate your configuration, refer to the `sigul-pesign-bridge config` command.

use std::{num::NonZeroU64, path::PathBuf};

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};

/// The configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// The systemd credentials ID of the Sigul client configuration.
    ///
    /// This configuration file includes the password to access the NSS database that contains the
    /// client certificate used to authenticate with the Sigul server. As such, it is expected to
    /// be provided by systemd's "ImportCredential" or "LoadCredentialEncrypted" option.
    ///
    /// # Example
    ///
    /// To prepare the encrypted configuration:
    ///
    /// ```bash
    /// systemd-creds encrypt /secure/ramfs/sigul-client-config /etc/credstore.encrypted/sigul.client.cconfig
    /// ```
    ///
    /// This will produce an encrypted blob which will be decrypted by systemd at runtime.
    pub sigul_client_config: PathBuf,

    /// The total length of time (in seconds) to wait for a signing request to complete.
    ///
    /// The service will retry requests to the Sigul server until it succeeds or
    /// this timeout is reached, at which point it will signal to the pesign-client
    /// that the request failed.
    pub request_timeout_secs: NonZeroU64,

    /// A list of signing keys available for use.
    ///
    /// Each key must be accessible to the Sigul client user in the Sigul
    /// server. The pesign-client specifies the key it wants to sign its
    /// request. If the requested key is not in this list, the request is
    /// rejected.
    pub keys: Vec<Key>,
}

/// A signing key and certificate pair.
///
/// When the sigul client requests that a PE be signed, it must specify a
/// signing key and a certificate to use. Additionally, it must provide a
/// passphrase to use the requested signing key.
///
/// If the pesign-client requests a signature from a [`Key`] that is not in the
/// [`Config`], its request is rejected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key {
    /// The name of the key in the Sigul server.
    pub key_name: String,
    /// The name of the certificate in the Sigul server.
    pub certificate_name: String,
    /// The systemd credential ID containing the passphrase.
    pub passphrase_path: PathBuf,
    /// If set, the service will validate the PE has been signed with the given
    /// certificate before returning the signed file to the client.
    ///
    /// This validation is done with the `sbverify` application, which must be
    /// installed to use this option. This is optional, and if unset, no signature
    /// validation is performed before passing the result back to the pesign-client.
    pub certificate_file: Option<PathBuf>,
}

impl Default for Key {
    fn default() -> Self {
        Self {
            key_name: "signing-key".to_string(),
            certificate_name: "codesigning".to_string(),
            passphrase_path: PathBuf::from("sigul-signing-key-passphrase"),
            certificate_file: None,
        }
    }
}

impl Key {
    /// The Sigul passphrase protecting this key.
    #[doc(hidden)]
    pub fn passphrase(
        &self,
        credentials_directory: &std::path::Path,
    ) -> Result<String, anyhow::Error> {
        let credentials_path = credentials_directory.join(&self.passphrase_path);
        let mut passphrase = std::fs::read_to_string(credentials_path)?;
        if passphrase.contains('\n') {
            return Err(anyhow!(
                "Passphrase file {} contains a newline, which is not allowed.",
                self.passphrase_path.display()
            ));
        }

        passphrase.push('\0');
        Ok(passphrase)
    }
}

impl Config {
    /// Get the absolute path to the Sigul client configuration file.
    ///
    /// The configuration file is expected to be stored relative to the CREDENTIALS_DIRECTORY.
    #[doc(hidden)]
    pub fn sigul_client_config(&self, credentials_dir: &std::path::Path) -> PathBuf {
        credentials_dir.join(&self.sigul_client_config)
    }

    /// Check the configuration file for validity.
    ///
    /// An error is returned if the files referenced do not exist, or if any of them contain invalid
    /// values.
    #[doc(hidden)]
    pub fn validate(&self, credentials_dir: Option<&std::path::Path>) -> anyhow::Result<()> {
        if let Some(dir) = credentials_dir {
            if self
                .keys
                .iter()
                .map(|k| {
                    k.passphrase(dir)
                        .err()
                        .inspect(|e| tracing::error!(error=%e))
                })
                .any(|err| err.is_some())
            {
                return Err(anyhow!(
                    "One or more passphrase files are missing or contain newlines"
                ));
            }
        }

        if self.keys.iter().any(|key| key.certificate_file.is_some()) {
            let mut command = std::process::Command::new("sbverify");
            command.arg("--help");
            let output = command.output()?;
            if !output.status.success() {
                return Err(anyhow!(
                    "sbverify needs to be installed and functional: {:?}",
                    output
                ));
            }
        }

        Ok(())
    }
}

impl std::fmt::Display for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            toml::ser::to_string_pretty(&self).unwrap_or_default()
        )
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            request_timeout_secs: NonZeroU64::new(60 * 15).expect("Don't set the default to 0"),
            keys: vec![Key::default()],
            sigul_client_config: PathBuf::from("sigul-client-config"),
        }
    }
}

pub(crate) fn load(path: &str) -> anyhow::Result<Config> {
    let config = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read from path {path:?}"))?;
    tracing::info!(%path, "Read from configuration file");
    toml::from_str(&config)
        .inspect_err(|error| {
            eprintln!("Failed to parse configuration loaded from {path:?}:\n{error}");
            eprintln!("Example config file:\n\n{}", Config::default());
        })
        .context("configuration file is invalid")
}
