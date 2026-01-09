// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! All the cryptography-related operations are in this module.
//!
//! Sequoia is used for GPG signatures and for the symmetric encryption of keys managed by Siguldry.
//! OpenSSL is used for other signatures.

use std::{
    io::{Read, Write},
    path::PathBuf,
    process::Stdio,
};

use anyhow::Context;
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    object::{Attribute, AttributeType, ObjectClass},
    types::AuthPin,
};
use openssl::{
    cms::{CMSOptions, CmsContentInfo},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    pkey_ctx::PkeyCtx,
    rsa::Rsa,
    stack::Stack,
    symm::Cipher,
    x509::{self, X509},
};
use sequoia_openpgp::{
    Profile,
    cert::CipherSuite,
    crypto::Password,
    packet,
    parse::{
        Parse,
        stream::{DecryptionHelper, DecryptorBuilder, VerificationHelper},
    },
    policy::StandardPolicy,
    serialize::{
        MarshalInto,
        stream::{Armorer, Encryptor, LiteralWriter, Message, Signer},
    },
    types::{KeyFlags, SymmetricAlgorithm},
};
use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;

use crate::{
    protocol::{self, DigestAlgorithm, KeyAlgorithm},
    server::{config::Pkcs11Binding, db},
};

pub(crate) fn generate_password() -> anyhow::Result<Password> {
    let mut buf = [0; 128];
    openssl::rand::rand_bytes(buf.as_mut_slice())?;
    Ok(Password::from(openssl::base64::encode_block(&buf)))
}

pub fn create_encrypted_key(
    config: &super::Config,
    user_password: Password,
    algorithm: KeyAlgorithm,
) -> anyhow::Result<(String, Vec<u8>, String, String)> {
    let key_password = generate_password()?;
    let key = match algorithm {
        KeyAlgorithm::Rsa4K => PKey::from_rsa(Rsa::generate(4096)?)?,
        KeyAlgorithm::P256 => PKey::from_ec_key(EcKey::generate(
            EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?.as_ref(),
        )?)?,
    };
    let public_key_pem = String::from_utf8(key.public_key_to_pem()?)?;
    let private_key_pem = key_password.map(|key_password| {
        key.private_key_to_pem_pkcs8_passphrase(openssl::symm::Cipher::aes_256_cbc(), key_password)
    })?;
    let private_key_pem = String::from_utf8(private_key_pem)?;
    let encrypted_password =
        encrypt_key_password(&config.pkcs11_bindings, user_password, key_password)?;
    let handle = format!(
        "{:X?}",
        openssl::hash::hash(MessageDigest::sha256(), &key.public_key_to_der()?)?
    );

    Ok((handle, encrypted_password, private_key_pem, public_key_pem))
}

/// A GPG key.
#[derive(Debug, Clone, PartialEq)]
pub struct GpgKey {
    cert: sequoia_openpgp::Cert,
    encrypted_password: Vec<u8>,
    user_password: Password,
}

impl GpgKey {
    pub fn from_armored_key(
        encrypted_key: &[u8],
        encrypted_password: Vec<u8>,
        user_password: Password,
    ) -> anyhow::Result<GpgKey> {
        let cert = sequoia_openpgp::Cert::from_bytes(encrypted_key)?;

        Ok(GpgKey {
            cert,
            encrypted_password,
            user_password,
        })
    }

    /// Create a new GPG key bound to the server.
    pub fn new<U: Into<packet::UserID>>(
        bindings: &[Pkcs11Binding],
        user_id: U,
        user_password: Password,
        profile: Profile,
        cipher: CipherSuite,
    ) -> anyhow::Result<GpgKey> {
        let key_password = generate_password()?;
        let encrypted_password =
            encrypt_key_password(bindings, user_password.clone(), key_password.clone())?;
        let (cert, _signature) = sequoia_openpgp::cert::CertBuilder::new()
            .set_profile(profile)?
            .set_cipher_suite(cipher)
            .add_userid(user_id)
            .set_primary_key_flags(KeyFlags::signing())
            //.add_signing_subkey()
            .set_password(Some(key_password))
            .generate()?;

        Ok(GpgKey {
            cert,
            encrypted_password,
            user_password,
        })
    }

    /// Get the encrypted, ASCII-armored private key.
    pub fn armored_key(&self) -> anyhow::Result<Vec<u8>> {
        self.cert.as_tsk().armored().to_vec()
    }

    pub fn public_key(&self) -> anyhow::Result<String> {
        Ok(String::from_utf8(
            self.cert
                .clone()
                .strip_secret_key_material()
                .armored()
                .to_vec()?,
        )?)
    }

    /// Get the hex GPG fingerprint.
    pub fn fingerprint(&self) -> String {
        self.cert.fingerprint().to_hex()
    }

    pub fn encrypted_password(&self) -> &[u8] {
        &self.encrypted_password
    }

    pub fn sign(&self, blob: &[u8]) -> anyhow::Result<Vec<u8>> {
        let policy = &StandardPolicy::new();
        let signing_key = self
            .cert
            .keys()
            .secret()
            .with_policy(policy, None)
            .supported()
            .for_signing()
            .nth(0)
            .unwrap()
            .key()
            .clone()
            .into_keypair()
            .unwrap();
        // TODO probably want SignatureBuilder
        let mut sink = vec![];
        {
            let message = Message::new(&mut sink);
            let message = Signer::new(message, signing_key).unwrap().build().unwrap();
            let mut message = LiteralWriter::new(message).build().unwrap();
            message.write_all(blob).unwrap();
            message.finalize().unwrap();
        }

        Ok(sink)
    }
}

/// The intermediate data format for passwords.
///
/// A key password, used to decrypt the actual signing key, never leaves the server. Instead,
/// it's encrypted using a set of server-side RSA keys which are stored in a PKCS#11 token,
/// which is then encrypted with a user's access password.
///
/// This is serialized to JSON, which looks like:
///
/// `{"None": {"password": "my-password"}}`
///
/// or
///
/// `{"Pkcs11": {"key_fingerprint": "hexencodedsha256sum", "password": "-----BEGIN PKCS7-----..." `
#[derive(Debug, Clone, Serialize, Deserialize)]
enum BoundPassword {
    /// No binding was used.
    None { password: String },
    /// Secrets bound by asymmetric keys stored in a device accessible via PKCS#11.
    ///
    /// Secrets of this variant have been encrypted using OpenSSL's CMS interface and the
    /// results are PEM-encoded.
    ///
    /// Examples of key stores include SoftHSMv2 or any HSM that provides a PKCS#11 interface,
    /// Yubikeys via the libykcs11 library, and Trusted Platform Modules (TPMs) via the
    /// libtpm2_pkcs11 library. Creating and managing the key pairs is up to the administrator.
    Pkcs11WithCMS {
        /// The SHA256 digest of the key used in this binding.
        key_fingerprint: String,
        /// The key password that's been encrypted by the public key identified in `key_fingerprint`.
        /// The string contains a PEM-encoded CMS structure.
        password: String,
    },
}

// I think this is the JSON format used by sigul for pkcs11. It'll be a list for most entries,
// but some old ones are dictionaries. Additionally, sigul theoretically supports recursive
// binding but that does appear to actually be used. This structure will be useful for writing
// the migration script later.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
struct SigulPkcs11BoundPassword {
    method: String,
    value: String,
    token: String,
}

/// Decrypt a key password to enable access to the key itself.
pub async fn decrypt_key_password(
    bindings: &[Pkcs11Binding],
    user_password: Password,
    data: &[u8],
) -> anyhow::Result<Password> {
    let key_bindings: Vec<BoundPassword> =
        symmetric_decrypt(user_password, data).map(|data| serde_json::from_slice(&data))??;

    for bound_password in key_bindings {
        match bound_password {
            BoundPassword::None { password } => return Ok(Password::from(password)),
            BoundPassword::Pkcs11WithCMS {
                key_fingerprint,
                password,
            } => {
                for binding in bindings.iter().filter(|binding| binding.can_unbind()) {
                    if let Ok(password) =
                        binding_decrypt(binding.clone(), password.clone().into_bytes())
                            .await
                            .map(Password::from)
                    {
                        return Ok(password);
                    } else {
                        tracing::debug!(
                            public_key = key_fingerprint,
                            key_uri = binding.private_key,
                            "Failed to unbind key password"
                        );
                    }
                }
            }
        }
    }

    Err(anyhow::anyhow!("Unable to unbind key password"))
}

/// Encrypt a key password for storage.
pub fn encrypt_key_password(
    bindings: &[Pkcs11Binding],
    user_password: Password,
    key_password: Password,
) -> anyhow::Result<Vec<u8>> {
    let mut bound_passwords = bindings
        .iter()
        .map(|binding| {
            tracing::info!(public_key=?binding.public_key, "Binding key password");
            key_password.map(|key| binding_encrypt(binding, key))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // If no bindings are configured, the key is only encrypted with the user password
    if bound_passwords.is_empty() {
        let none_binding = key_password.map(|p| {
            let password = String::from_utf8(p.to_vec())?;
            Ok::<_, anyhow::Error>(BoundPassword::None { password })
        })?;
        bound_passwords.push(none_binding);
    }

    symmetric_encrypt(
        user_password,
        serde_json::to_vec(&bound_passwords)?.as_slice(),
    )
}

/// Implement a helper for unsigned, symmetrically encrypted data for Sequoia.
struct SymmetricHelper {
    password: Password,
}

// Decrypt exclusively via symmetrically encrypted session keys.
impl DecryptionHelper for SymmetricHelper {
    fn decrypt(
        &mut self,
        _pkesks: &[sequoia_openpgp::packet::PKESK],
        symmetric_session_keys: &[sequoia_openpgp::packet::SKESK],
        _sym_algo: Option<sequoia_openpgp::types::SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(
            Option<sequoia_openpgp::types::SymmetricAlgorithm>,
            &sequoia_openpgp::crypto::SessionKey,
        ) -> bool,
    ) -> sequoia_openpgp::Result<Option<sequoia_openpgp::Cert>> {
        for session_key in symmetric_session_keys {
            if session_key
                .decrypt(&self.password)
                .map(|(algorithm, session_key)| decrypt(algorithm, &session_key))
                .unwrap_or(false)
            {
                return Ok(None);
            }
        }
        Err(anyhow::anyhow!("Bad passphrase"))
    }
}

// A no-op verification helper implementation since the data is not expected to be signed.
impl VerificationHelper for SymmetricHelper {
    fn get_certs(
        &mut self,
        _ids: &[sequoia_openpgp::KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<sequoia_openpgp::Cert>> {
        Ok(vec![])
    }

    fn check(
        &mut self,
        _structure: sequoia_openpgp::parse::stream::MessageStructure<'_>,
    ) -> sequoia_openpgp::Result<()> {
        Ok(())
    }
}

/// Encrypts some data with the given [`Password`] using GPG.
///
/// Returns the ASCII-armored, encrypted `key_passphrase`.
fn symmetric_encrypt(password: Password, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut buffer = vec![];
    {
        let message = Armorer::new(Message::new(&mut buffer)).build()?;
        let encryptor = Encryptor::with_passwords(message, Some(password))
            .symmetric_algo(SymmetricAlgorithm::AES256)
            .build()?;
        let mut message = LiteralWriter::new(encryptor).build()?;
        message.write_all(data)?;
        message.finalize()?;
    }

    Ok(buffer)
}

/// Decrypt data using GPG.
///
/// This is the inverse of [`symmetric_encrypt`]. Data is not expected to be signed and signatures are not checked.
fn symmetric_decrypt(password: Password, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let policy = StandardPolicy::new();
    let helper = SymmetricHelper { password };
    let mut decryptor = DecryptorBuilder::from_bytes(&data)?.with_policy(&policy, None, helper)?;
    let mut user_passphrase = vec![];
    decryptor.read_to_end(&mut user_passphrase)?;

    Ok(user_passphrase)
}

/// Encrypt some data using a [`Binding`] configuration.
///
/// The options here are primarily chosen because they match Sigul.
fn binding_encrypt(binding: &Pkcs11Binding, data: &[u8]) -> anyhow::Result<BoundPassword> {
    let certificate = std::fs::read_to_string(&binding.public_key)?;
    let certificate = X509::from_pem(certificate.as_bytes())?;
    let mut cert_stack = Stack::new()?;
    cert_stack.push(certificate)?;
    let encrypted = CmsContentInfo::encrypt(
        &cert_stack,
        data,
        Cipher::aes_256_cbc(),
        CMSOptions::empty(),
    )?;
    let pem = encrypted.to_pem()?;
    let certificate = cert_stack.pop().expect("we just pushed a cert");
    let key_fingerprint = format!("{:X?}", &certificate.digest(MessageDigest::sha256())?);
    Ok(BoundPassword::Pkcs11WithCMS {
        key_fingerprint,
        password: String::from_utf8(pem)?,
    })
}

/// Decrypt a bound password using a PIN-protected private key in a PKCS11 token.
async fn binding_decrypt(binding: Pkcs11Binding, data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let output = tokio::task::spawn_blocking(move || {
        let private_key = binding.private_key.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "Binding configuration is missing the 'private_key' field and can't be used to decrypt"
            )
        })?;
        // In the future maybe we'll get openssl provider APIs? Alternatively, if Sequioa gets
        // PKCS#11 support, we could switch to using it in a migration.
        let mut command = std::process::Command::new("openssl");
        let mut child = command
            .args([
                "cms",
                "-decrypt",
                "-inform",
                "pem",
                "-provider",
                "pkcs11",
                "-passin",
                "stdin",
                "-inkey",
            ])
            .arg(private_key)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("openssl-cms command missing stdin"))?;

        binding.pin.ok_or_else(||anyhow::anyhow!("Binding must include a PIN"))?.map(|pin| {
            stdin.write_all(pin)
        })?;
        stdin.write_all(b"\n")?;
        stdin.write_all(&data)?;
        drop(stdin);

        let output = child.wait_with_output()?;
        Ok::<_, anyhow::Error>(output)
    }).await??;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to decrypt data via PKCS#11 using openssl-cms (exited {:?}): {stderr}",
            output.status.code()
        ));
    }

    Ok(output.stdout)
}

/// Import keys and certificates from a PKCS#11 token.
///
/// This creates records for the key pairs stored in a PKCS#11 module, along with any x509 certificates
/// associated with them.
pub async fn import_pkcs11_token(
    conn: &mut SqliteConnection,
    module: PathBuf,
    token_user_pin: AuthPin,
) -> anyhow::Result<db::Pkcs11Token> {
    let pkcs11 = Pkcs11::new(&module).context("Failed to load the PKCS#11 module specified.")?;
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .context("Failed to initialized the PKCS#11 module")?;
    let result = import_pkcs11_token_private(&pkcs11, conn, module, token_user_pin).await;
    pkcs11.finalize()?;
    result
}

async fn import_pkcs11_token_private(
    pkcs11: &Pkcs11,
    conn: &mut SqliteConnection,
    module: PathBuf,
    token_user_pin: AuthPin,
) -> anyhow::Result<db::Pkcs11Token> {
    let slot = pkcs11
        .get_slots_with_token()?
        .pop()
        .ok_or_else(|| anyhow::anyhow!("The provided token has no slots"))?;
    let token_info = pkcs11
        .get_token_info(slot)
        .context("Unable to read token information")?;
    let session = pkcs11
        .open_ro_session(slot)
        .context("Unable to open a read-only session with the token")?;
    session
        .login(cryptoki::session::UserType::User, Some(&token_user_pin))
        .context("Failed to login to the token with the provided user PIN")?;

    let manufacturer_id = if token_info.manufacturer_id().is_empty() {
        None
    } else {
        Some(token_info.manufacturer_id().to_string())
    };
    let model = if token_info.model().is_empty() {
        None
    } else {
        Some(token_info.model().to_string())
    };
    let label = if token_info.label().is_empty() {
        return Err(anyhow::anyhow!("PKCS #11 token needs to have a label"));
    } else {
        token_info.label().to_string()
    };
    let serial_number = if token_info.serial_number().is_empty() {
        return Err(anyhow::anyhow!(
            "PKCS #11 token needs to have a serial_number"
        ));
    } else {
        token_info.serial_number().to_string()
    };
    let token =
        db::Pkcs11Token::create(conn, module, label, manufacturer_id, model, serial_number).await?;

    // Look through the private keys, then match them up with related public key and certificates
    // using the Id attribute. Once all the bits are collect them, add them to the database.
    struct TokenKey {
        label: String,
        key_type: cryptoki::object::KeyType,
        public_key_der: Option<Vec<u8>>,
        x509_certificate_pem: Option<String>,
    }
    let mut token_keys: std::collections::HashMap<Vec<u8>, TokenKey> =
        std::collections::HashMap::new();
    let private_key_attributes = [
        AttributeType::Id,
        AttributeType::Label,
        AttributeType::KeyType,
        AttributeType::Class,
    ];
    for object in session
        .iter_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])
        .context("Failed to search private key objects")?
    {
        let object = object?;
        let attributes = session
            .get_attributes(object, &private_key_attributes)
            .context("Failed to query private key attributes")?;

        let mut key_id = None;
        let mut label = None;
        let mut key_type = None;

        for attr in attributes {
            match attr {
                Attribute::Id(id) => key_id = Some(id),
                Attribute::Label(l) => {
                    label = String::from_utf8(l).ok();
                }
                Attribute::KeyType(kt) => key_type = Some(kt),
                _ => {}
            }
        }

        if let (Some(id), Some(label), Some(key_type)) = (key_id, label, key_type) {
            token_keys.insert(
                id,
                TokenKey {
                    label,
                    key_type,
                    public_key_der: None,
                    x509_certificate_pem: None,
                },
            );
        }
    }

    let public_key_attributes = [AttributeType::Id, AttributeType::PublicKeyInfo];
    for object in session
        .iter_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY)])
        .context("Failed to search public key objects")?
    {
        let object = object?;
        let attributes = session
            .get_attributes(object, &public_key_attributes)
            .context("Failed to query public key attributes")?;

        let mut key_id = None;
        let mut public_key_info = None;

        for attr in attributes {
            match attr {
                Attribute::Id(id) => key_id = Some(id),
                Attribute::PublicKeyInfo(der) => public_key_info = Some(der),
                _ => {}
            }
        }

        if let (Some(id), Some(der)) = (key_id, public_key_info)
            && let Some(entry) = token_keys.get_mut(&id)
        {
            entry.public_key_der = Some(der);
        }
    }

    // Pull out any certificates in the token for the key pairs we know about
    let certificate_attributes = [AttributeType::Id, AttributeType::Value];
    for object in session
        .iter_objects(&[Attribute::Class(ObjectClass::CERTIFICATE)])
        .context("Failed to search certificate objects")?
    {
        let object = object?;
        let attributes = session
            .get_attributes(object, &certificate_attributes)
            .context("Failed to query certificate attributes")?;

        let mut key_id = None;
        let mut cert_der = None;

        for attr in attributes {
            match attr {
                Attribute::Id(id) => key_id = Some(id),
                Attribute::Value(der) => cert_der = Some(der),
                _ => {}
            }
        }

        if let (Some(id), Some(der)) = (key_id, cert_der)
            && let Some(entry) = token_keys.get_mut(&id)
        {
            let pem = x509::X509::from_der(&der)
                .and_then(|cert| cert.to_pem())
                .ok()
                .and_then(|pem_bytes| String::from_utf8(pem_bytes).ok());
            entry.x509_certificate_pem = pem;
        }
    }

    for (key_id, key_info) in &token_keys {
        if let Some(public_key) = key_info
            .public_key_der
            .as_deref()
            .map(openssl::pkey::PKey::public_key_from_der)
        {
            let public_key = public_key?;
            let key_algorithm = match key_info.key_type {
                cryptoki::object::KeyType::EC => {
                    let ecc_key = public_key.ec_key()?;
                    if ecc_key.group().curve_name() == Some(Nid::X9_62_PRIME256V1) {
                        KeyAlgorithm::P256
                    } else {
                        tracing::warn!(
                            label = key_info.label,
                            "Found unsupported ECC key; skipping"
                        );
                        continue;
                    }
                }
                cryptoki::object::KeyType::RSA => {
                    // Double check it's an RSA key
                    let _ = public_key.rsa()?;
                    match public_key.bits() {
                        4096 => KeyAlgorithm::Rsa4K,
                        other => {
                            tracing::warn!(
                                label = key_info.label,
                                "Found unsupported RSA key of size {}",
                                other
                            );
                            continue;
                        }
                    }
                }
                unsupported => {
                    tracing::warn!(
                        label = key_info.label,
                        "Found unsupported key type {:?}",
                        unsupported
                    );
                    continue;
                }
            };

            let pubkey_pem = String::from_utf8(public_key.public_key_to_pem()?)?;
            let handle = format!(
                "{:X?}",
                openssl::hash::hash(MessageDigest::sha256(), &public_key.public_key_to_der()?)?
            );
            let key_material = format!("{:X?}", key_id);
            let key = db::Key::create(
                conn,
                &key_info.label,
                &handle,
                key_algorithm,
                db::KeyPurpose::Signing,
                &key_material,
                &pubkey_pem,
                Some(&token),
            )
            .await?;
            if let Some(data) = key_info.x509_certificate_pem.clone() {
                db::PublicKeyMaterial::create(conn, &key, db::PublicKeyMaterialType::X509, data)
                    .await?;
            }
        }
    }

    Ok(token)
}

/// Sign a set of digests with the given key.
pub fn sign(
    key: &db::Key,
    password: &Password,
    digests: Vec<(DigestAlgorithm, String)>,
) -> anyhow::Result<Vec<protocol::json::Signature>> {
    // TODO: This is exclusively for nonPGP soft keys
    let pkey = match key.key_algorithm {
        KeyAlgorithm::Rsa4K => password
            .map(|password| {
                Rsa::private_key_from_pem_passphrase(key.key_material.as_bytes(), password)
            })
            .and_then(PKey::from_rsa),
        KeyAlgorithm::P256 => password
            .map(|password| {
                EcKey::private_key_from_pem_passphrase(key.key_material.as_bytes(), password)
            })
            .and_then(PKey::from_ec_key),
    }?;

    let mut signatures = Vec::with_capacity(digests.len());
    for (algorithm, hex_hash) in digests {
        let hash = hex::decode(&hex_hash).context("The digest provided was not valid hex")?;
        if hash.len() != algorithm.size() {
            return Err(anyhow::anyhow!(
                "The specified digest algorithm is {} bytes; payload was {}",
                algorithm.size(),
                hash.len()
            ));
        }

        let mut ctx = PkeyCtx::new(&pkey)?;
        ctx.sign_init()?;
        ctx.set_signature_md(algorithm.into())?;
        if key.key_algorithm == KeyAlgorithm::Rsa4K {
            // PKCS #1 should be the default, but lets be explicit about it.
            ctx.set_rsa_padding(openssl::rsa::Padding::PKCS1)?;
        }
        let mut signature = vec![];
        ctx.sign_to_vec(&hash, &mut signature)?;
        signatures.push(protocol::json::Signature {
            signature,
            digest: algorithm,
            hash: hex_hash,
        });
    }

    Ok(signatures)
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use anyhow::Result;
    use cryptoki::{mechanism::Mechanism, session::UserType};
    use tempfile::{NamedTempFile, TempDir};

    use super::*;

    // Generated passwords should be base64 encoded and 128 bytes of randomness.
    #[test]
    fn password_len() -> anyhow::Result<()> {
        let password = generate_password()?;
        let string = password.map(|p| String::from_utf8(p.to_vec()))?;
        let bytes = openssl::base64::decode_block(&string)?;
        assert_eq!(128, bytes.len());

        Ok(())
    }
    // Encrypting and then decrypting should give us the key back
    #[test]
    fn encrypt_decrypt() -> Result<()> {
        let user_passphrase = Password::from("this grants a user access to the key passphrase");
        let data = "this encrypts the private key";
        let encrypted_data = symmetric_encrypt(user_passphrase.clone(), data.as_bytes())?;
        let decrypted_data = symmetric_decrypt(user_passphrase, &encrypted_data)?;
        assert_eq!(data.as_bytes(), decrypted_data);
        Ok(())
    }

    // Ensure something encrypted with sq's CLI is decrypted by our implementation
    #[test]
    fn encrypt_with_sq_decrypt() -> Result<()> {
        let user_passphrase = "this grants a user access to the key passphrase".to_string();
        let data = "this encrypts the private key";
        let mut password_file = NamedTempFile::new()?;
        let mut message = NamedTempFile::new()?;
        password_file.write_all(user_passphrase.as_bytes())?;
        message.write_all(data.as_bytes())?;

        let mut command = std::process::Command::new("sq");
        let result = command
            .arg("encrypt")
            .arg(format!(
                "--with-password-file={}",
                password_file.path().display()
            ))
            .arg("--without-signature")
            .arg(message.path())
            .output()?;

        let retrieved_key_passphrase =
            symmetric_decrypt(Password::from(user_passphrase), &result.stdout)?;
        assert_eq!(data.as_bytes(), retrieved_key_passphrase);
        Ok(())
    }

    // Ensure something encrypted with our implementation is decryptable by sq's CLI
    #[test]
    fn encrypt_decrypt_with_sq() -> Result<()> {
        let user_passphrase = "this grants a user access to the key passphrase".to_string();
        let data = "this encrypts the private key";
        let encrypted_passphrase =
            symmetric_encrypt(Password::from(user_passphrase.as_bytes()), data.as_bytes())?;
        let mut password_file = NamedTempFile::new()?;
        let mut encrypted_message = NamedTempFile::new()?;
        password_file.write_all(user_passphrase.as_bytes())?;
        encrypted_message.write_all(&encrypted_passphrase)?;

        let mut command = std::process::Command::new("sq");
        let result = command
            .arg(format!(
                "--password-file={}",
                password_file.path().display()
            ))
            .arg("decrypt")
            .arg(encrypted_message.path())
            .output()?;
        assert_eq!(data.as_bytes(), result.stdout);

        Ok(())
    }

    #[derive(Debug)]
    struct Hsm {
        _directory: TempDir,
        bindings: Vec<Pkcs11Binding>,
    }

    // Set up a temporary PKCS#11 token.
    //
    // Note that tests using this must alter their environment which is not thread safe.
    // Thus, you will see failures if you don't use nextest.
    fn setup_hsm() -> anyhow::Result<Hsm> {
        let hsm_dir = TempDir::new()?;
        let hsm_config_path = hsm_dir.path().join("kryoptic.toml");
        let hsm_db_path = hsm_dir.path().join("kryoptic.sql");
        std::fs::write(
            &hsm_config_path,
            format!(
                "[[slots]]\nslot = 1\ndbtype = \"sqlite\"\ndbargs = \"{}\"",
                hsm_db_path.display()
            ),
        )?;
        // SAFETY:
        // These tests are required to run with nextest, which starts a new process for each test.
        // Using set_var is only safe if no other code is interacting with the environment variables,
        // which should be true under nextest. Refer to
        // https://nexte.st/docs/configuration/env-vars/#altering-the-environment-within-tests to ensure
        // this remains the case with current versions of Rust.
        unsafe {
            std::env::set_var("KRYOPTIC_CONF", &hsm_config_path);
        };

        let module_path = "/usr/lib64/pkcs11/libkryoptic_pkcs11.so";
        let pkcs11 = Pkcs11::new(module_path).context("Install the kryoptic PKCS#11 module")?;
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .context("Failed to initialized kryoptic PKCS#11 module")?;
        let slot = pkcs11
            .get_slots_with_token()?
            .pop()
            .expect("no slot available");
        let so_pin = AuthPin::new("12345678".into());
        let user_pin = AuthPin::new("secret-password".into());
        pkcs11
            .init_token(slot, &so_pin, "test")
            .context("Failed to initialize token")?;
        pkcs11
            .open_rw_session(slot)
            .and_then(|session| {
                session.login(UserType::So, Some(&so_pin))?;
                session.init_pin(&user_pin)?;

                session.generate_key_pair(
                    &Mechanism::RsaPkcsKeyPairGen,
                    &[
                        Attribute::Id(vec![1]),
                        Attribute::Label(b"binding-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(false),
                        Attribute::Verify(true),
                        Attribute::Encrypt(true),
                        Attribute::ModulusBits(4096.into()),
                    ],
                    &[
                        Attribute::Id(vec![1]),
                        Attribute::Label(b"binding-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Sign(true),
                        Attribute::Decrypt(true),
                    ],
                )?;

                // Annoyingly it doesn't seem possible to convert the named curve Nid to ASN.1, so we manually
                // create it from the OID for NIST P-256. Furthermore, converting the Asn1Object to bytes doesn't
                // include the tag or length, just the value, so we have to manually do that too.
                let p256_oid = openssl::asn1::Asn1Object::from_str("1.2.840.10045.3.1.7")
                    .expect("This is the NIST P-256 OID");
                let oid_content = p256_oid.as_slice();
                let mut p256_oid_bytes: Vec<u8> = vec![0x06, oid_content.len() as u8];
                p256_oid_bytes.extend_from_slice(oid_content);
                session.generate_key_pair(
                    &Mechanism::EccKeyPairGen,
                    &[
                        Attribute::Id(vec![2]),
                        Attribute::Label(b"ecc-test-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(false),
                        Attribute::EcParams(p256_oid_bytes),
                        Attribute::Verify(true),
                    ],
                    &[
                        Attribute::Id(vec![2]),
                        Attribute::Label(b"ecc-test-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Sign(true),
                    ],
                )?;

                // Add unsupported key
                session.generate_key_pair(
                    &Mechanism::RsaPkcsKeyPairGen,
                    &[
                        Attribute::Id(vec![3]),
                        Attribute::Label(b"unsupported-rsa-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(false),
                        Attribute::Verify(true),
                        Attribute::ModulusBits(1024.into()),
                    ],
                    &[
                        Attribute::Id(vec![3]),
                        Attribute::Label(b"unsupported-rsa-key".to_vec()),
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Sign(true),
                    ],
                )?;
                Ok(())
            })
            .context("Failed to initialize user pin")?;

        pkcs11.finalize()?;

        let rsa_key_uri = "pkcs11:model=v1;manufacturer=Kryoptic%20Project;token=test;id=%01;object=binding-key;type=private";
        let cert_file = hsm_dir.path().join("cert0");
        let mut command = Command::new("openssl");
        let output = command
            .env("KRYOPTIC_CONF", &hsm_config_path)
            .args([
                "req",
                "-x509",
                "-provider",
                "pkcs11",
                "-passin",
                "pass:secret-password",
                "-subj",
                "/CN=BindingKey",
            ])
            .arg("-key")
            .arg(rsa_key_uri)
            .arg("-out")
            .arg(&cert_file)
            .output()?;
        if !output.status.success() {
            panic!(
                "Failed to create x509 certificate:  {:?}",
                String::from_utf8_lossy(&output.stderr)
            )
        }

        let mut command = Command::new("pkcs11-tool");
        let output = command
            .env("KRYOPTIC_CONF", &hsm_config_path)
            .arg(format!("--module={}", module_path))
            .args([
                "--login",
                "--pin=secret-password",
                "--type=cert",
                "--label=self-signed-cert",
                "--id=1",
            ])
            .arg(format!("--write-object={}", cert_file.display()))
            .output()?;
        if !output.status.success() {
            panic!(
                "Failed to add cert to SoftHSM token: {:?}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let binding = Pkcs11Binding {
            public_key: cert_file,
            private_key: Some(rsa_key_uri.to_string()),
            pin: Some(Password::from("secret-password")),
        };

        // Some other bindings we don't have keys for, but should still encrypt for.
        let mut bindings = vec![binding];
        for n in 1..5 {
            let pubkey_path = hsm_dir.path().join(format!("cert{}", n));
            let key_path = hsm_dir.path().join(format!("cert{}.key", n));
            let mut command = Command::new("openssl");
            command
                .args([
                    "req", "-x509", "-new", "-nodes", "-sha256", "-subj", "/CN=Test", "-days", "5",
                    "-newkey", "rsa:4096", "-keyout",
                ])
                .arg(&key_path)
                .arg("-out")
                .arg(&pubkey_path);
            let output = command.output()?;
            if !output.status.success() {
                panic!(
                    "Failed to create binding cert: {:?}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            bindings.push(Pkcs11Binding {
                public_key: pubkey_path,
                ..Default::default()
            });
        }

        Ok(Hsm {
            _directory: hsm_dir,
            bindings,
        })
    }

    /// Assert encrypting and then decrypting for bindings works.
    #[tokio::test]
    async fn encrypt_decrypt_binding() -> Result<()> {
        let softhsm = setup_hsm()?;

        let binding = softhsm.bindings.first().unwrap();
        let bound_password = binding_encrypt(binding, b"some data")?;
        let decrypted_data = match bound_password {
            BoundPassword::None { password: _ } => {
                panic!("We should have encrypted it with a certificate")
            }
            BoundPassword::Pkcs11WithCMS {
                key_fingerprint: _,
                password,
            } => binding_decrypt(binding.to_owned(), password.into_bytes()).await,
        }?;

        assert_eq!(b"some data".as_slice(), decrypted_data);

        Ok(())
    }

    /// Assert the complete encryption/decryption process roundtrips as expected.
    #[tokio::test]
    async fn encrypt_decrypt_key_password() -> Result<()> {
        let softhsm = setup_hsm()?;

        let key_password = Password::from("a secret that never leaves the server");
        let user_password = Password::from("some long password clients provide");
        let blob = encrypt_key_password(
            &softhsm.bindings,
            user_password.clone(),
            key_password.clone(),
        )?;
        let roundtrip_key_password =
            decrypt_key_password(&softhsm.bindings, user_password, &blob).await?;

        assert_eq!(key_password, roundtrip_key_password);

        Ok(())
    }

    // Assert if no bindings include keys, we get an error
    #[tokio::test]
    async fn encrypt_decrypt_key_password_binding_no_key() -> Result<()> {
        let softhsm = setup_hsm()?;

        let key_password = Password::from("a secret that never leaves the server");
        let user_password = Password::from("some long password clients provide");
        let blob = encrypt_key_password(
            &softhsm.bindings,
            user_password.clone(),
            key_password.clone(),
        )?;
        let result =
            decrypt_key_password(softhsm.bindings.get(1..).unwrap(), user_password, &blob).await;
        assert!(result.is_err_and(|err| err.to_string().contains("Unable to unbind key password")));

        Ok(())
    }

    // We should get an error if the user password is incorrect
    #[tokio::test]
    async fn encrypt_decrypt_key_password_wrong_user_password() -> Result<()> {
        let softhsm = setup_hsm()?;

        let key_password = Password::from("a secret that never leaves the server");
        let user_password = Password::from("some long password clients provide");
        let blob = encrypt_key_password(&softhsm.bindings, user_password, key_password.clone())?;
        let user_password = Password::from("the wrong password");
        let result =
            decrypt_key_password(softhsm.bindings.get(1..).unwrap(), user_password, &blob).await;
        assert!(result.is_err_and(|err| err.to_string().contains("Bad passphrase")));

        Ok(())
    }

    // Assert if no bindings are configured, just the user password is sufficient.
    #[tokio::test]
    async fn encrypt_decrypt_key_password_no_bindings() -> Result<()> {
        let key_password = Password::from("a secret that never leaves the server");
        let user_password = Password::from("some long password clients provide");
        let blob = encrypt_key_password(&[], user_password.clone(), key_password.clone())?;
        let roundtrip_key_password = decrypt_key_password(&[], user_password, &blob).await?;
        assert_eq!(key_password, roundtrip_key_password);
        Ok(())
    }

    #[tokio::test]
    async fn import_pkcs11_keys() -> Result<()> {
        let _hsm = setup_hsm()?;
        let db_pool = db::pool("sqlite::memory:", false).await?;
        db::migrate(&db_pool).await?;
        let mut conn = db_pool.begin().await?;

        super::import_pkcs11_token(
            &mut conn,
            PathBuf::from("/usr/lib64/pkcs11/libkryoptic_pkcs11.so"),
            AuthPin::new("secret-password".into()),
        )
        .await?;

        let keys = db::Key::list(&mut conn).await?;
        assert_eq!(keys.len(), 2);
        for key in keys {
            if key.key_algorithm == KeyAlgorithm::Rsa4K {
                let certs =
                    db::PublicKeyMaterial::list(&mut conn, &key, db::PublicKeyMaterialType::X509)
                        .await?;
                assert_eq!(certs.len(), 1);
            } else {
                let certs =
                    db::PublicKeyMaterial::list(&mut conn, &key, db::PublicKeyMaterialType::X509)
                        .await?;
                assert_eq!(certs.len(), 0);
            }
        }

        Ok(())
    }
}
