// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::{fmt::Debug, io::Read, path::Path};

use crate::v2::error::ClientError as Error;

use openssl::{
    error::ErrorStack,
    ssl::{Ssl, SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode, SslVersion},
};

/// The TLS configuration used by the Siguldry client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    connector: SslConnector,
}

impl ClientConfig {
    /// Create a new TLS configuration for a Siguldry client.
    pub fn new<P: AsRef<Path>>(
        certificate: P,
        private_key: P,
        private_key_passphrase: Option<P>,
        certificate_authority: P,
    ) -> Result<Self, Error> {
        let mut connector = SslConnector::builder(SslMethod::tls())?;
        connector.set_verify(SslVerifyMode::PEER);
        // The Python version makes this configurable, and fails if the min version is less than 1.2
        connector.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        connector.set_max_proto_version(Some(SslVersion::TLS1_2))?;
        connector.set_ca_file(&certificate_authority)?;

        let mut private_key_buf = vec![];
        std::fs::File::open(private_key)?.read_to_end(&mut private_key_buf)?;
        let private_key = match &private_key_passphrase {
            Some(passphrase_path) => {
                let mut passphrase = vec![];
                std::fs::File::open(passphrase_path)?.read_to_end(&mut passphrase)?;
                openssl::pkey::PKey::private_key_from_pem_passphrase(&private_key_buf, &passphrase)?
            }
            None => openssl::pkey::PKey::private_key_from_pem(&private_key_buf)?,
        };
        connector.set_private_key(&private_key)?;
        connector.set_certificate_file(&certificate, SslFiletype::PEM)?;
        connector.check_private_key()?;

        Ok(Self {
            connector: connector.build(),
        })
    }

    /// Retrieve an SSL configuration acceptable to use when connecting to the provided hostname.
    pub(crate) fn ssl(&self, hostname: &str) -> Result<openssl::ssl::Ssl, ErrorStack> {
        let ssl = self.connector.configure()?.into_ssl(hostname)?;
        tracing::trace!(verify_mode=?ssl.ssl_context().verify_mode(), hostname=hostname, "Created SSL connection config");
        Ok(ssl)
    }
}

/// The TLS configuration used by the Sigul server.
#[derive(Clone)]
pub struct ServerConfig {
    acceptor: SslAcceptor,
}

impl Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig").finish()
    }
}

impl ServerConfig {
    /// Create a new TLS configuration for a Siguldry server.
    pub fn new<P: AsRef<Path>>(
        certificate: P,
        private_key: P,
        private_key_passphrase: Option<P>,
        client_ca: P,
    ) -> Result<Self, Error> {
        let mut private_key_buf = vec![];
        std::fs::File::open(private_key)
            .unwrap()
            .read_to_end(&mut private_key_buf)?;
        let private_key = match &private_key_passphrase {
            Some(passphrase_path) => {
                let mut passphrase = vec![];
                std::fs::File::open(passphrase_path)?.read_to_end(&mut passphrase)?;
                openssl::pkey::PKey::private_key_from_pem_passphrase(&private_key_buf, &passphrase)?
            }
            None => openssl::pkey::PKey::private_key_from_pem(&private_key_buf)?,
        };
        let f = std::fs::read_to_string(&client_ca)?;
        let client_ca_cert = openssl::x509::X509::from_pem(f.as_bytes())?;

        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        // TODO probaby should bump client up to 1.3
        acceptor.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        acceptor.add_client_ca(&client_ca_cert)?;
        acceptor.set_ca_file(client_ca)?;
        acceptor.set_private_key(&private_key)?;
        acceptor.set_certificate_file(&certificate, SslFiletype::PEM)?;
        acceptor.check_private_key()?;
        // TODO verify client CN matches username

        Ok(Self {
            acceptor: acceptor.build(),
        })
    }

    /// Retrieve an SSL configuration acceptable to use when accepting an incoming connection.
    pub(crate) fn ssl(&self) -> Result<openssl::ssl::Ssl, ErrorStack> {
        let ssl = Ssl::new(self.acceptor.context())?;
        tracing::trace!(verify_mode=?ssl.ssl_context().verify_mode(), "Created SSL connection config");
        Ok(ssl)
    }
}
