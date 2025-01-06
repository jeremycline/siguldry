# sigul-pesign-bridge

Drop-in replacement for pesign's daemon that bridges pesign-client requests to a Sigul server.

The service provides a Unix socket at, by default, `/run/pesign/socket`. `pesign-client` can be used to connect to this socket and request signatures for PE applications. Unlike `pesign`, this implementation forwards the request to a [sigul](https://pagure.io/sigul) signing server.

## Configuration

Configuration is provided via a TOML file. The current configuration (or the default, if none is provided) can be seen with:
```bash
sigul-pesign-bridge config
```

The configuration format with in-line documentation:

```toml
# The systemd credentials ID of the Sigul client configuration.
#
# This configuration file includes the password to access the NSS database that contains the
# client certificate used to authenticate with the Sigul server. As such, it is expected to
# be provided by systemd's "LoadCredentialsEncrypted" option.
#
# To prepare the encrypted configuration::
#
#   # systemd-creds encrypt /secure/ramfs/sigul-client.conf /etc/sigul-pesign-bridge/sigul-client.conf
#
# This will produce an encrypted blob which will be decrypted by systemd at runtime.
#  
# # Example
#
# Suppose the systemd unit file contains the following::
#  
#     [Service]
#     LoadCredentialsEncrypted=sigul-client-config:/etc/sigul-pesign-bridge/sigul-client.conf
#
# The credentials ID is "sigul-client-config". The decrypted file is provided to the service
# by systemd using the path "$CREDENTIALS_PATH/sigul-client-config".
sigul_client_config = "sigul-client-config"

# The total length of time (in seconds) to wait for a signing request to complete.
#
# The service will retry requests to the Sigul server until it succeeds or
# this timeout is reached, at which point it will signal to the pesign-client
# that the request failed. This must be a non-zero value.
request_timeout_secs = 600

# A list of signing keys available for use.
[[keys]]
# The name of the key in Sigul.
key_name = "signing-key"

# The name of the certificate in Sigul.
certificate_name = "codesigning"

# The ID used in the systemd encrypted credential.
passphrase_path = "sigul-signing-key-passphrase"

# If set, the service will validate the PE has been signed with the given certificate
# before returning the signed file to the client. This validation is done with the
# "sbverify" application, which must be installed to use this option. This field is
# optional.
certificate_file = "/path/to/signing/certificate.pem"

[[keys]]
key_name = "other-signing-key"
certificate_name = "other-codesigning"
passphrase_path = "other-sigul-signing-key-passphrase"
```

## Running

This document assumes the service is running under systemd using a unit file based off the one provided
at `sigul-pesign-bridge/sigul-pesign-bridge.service`. Some set up is required as the expectation is all
secrets are handled by systemd.

### Configuration

Place your TOML configuration at `/etc/sigul-pesign-bridge/config.toml`, which
is the default set in the systemd unit file. Alternatively, adjust the unit file.

### Secrets

To start with, a few secrets need to be prepared. Refer to [systemd's
credentials documentation](https://systemd.io/CREDENTIALS/) for details.

To begin, the Sigul client configuration should be encrypted. The client
configuration contains the password needed to access the Sigul client
certificate in the NSS database:

```bash
# Assuming your sigul client configuration is prepared at /secure/ramfs/sigul-client-config
systemd-creds encrypt /secure/ramfs/sigul-client-config /etc/sigul-pesign-bridge/sigul-client-config
```

Next, for each signing key in Sigul, we should configure the passphrase needed to unlock it:

```bash
# This will prompt you for both passwords.
systemd-ask-password -n | systemd-creds encrypt - /etc/sigul-pesign-bridge/sigul-signing-key-passphrase
systemd-ask-password -n | systemd-creds encrypt - /etc/sigul-pesign-bridge/other-sigul-signing-key-passphrase
```

The service rejects passphrase files with newlines, so if you use
`systemd-creds` directly for the passphrases, ensure they do not include
trailing newlines.

Finally, we must configure the systemd unit file to load the credentials. Either run

```bash
sudo systemctl edit sigul-pesign-bridge.service
```

or manually create `/etc/systemd/system/sigul-pesign-bridge.service.d/override.conf` and add an entry
for each credential. For the example configuration above, this would look like:

```ini
[Service]
LoadCredentialEncrypted=sigul-client-config:/etc/sigul-pesign-bridge/sigul-client-config
LoadCredentialEncrypted=sigul-signing-key-passphrase:/etc/sigul-pesign-bridge/sigul-signing-key-passphrase
LoadCredentialEncrypted=other-sigul-signing-key-passphrase:/etc/sigul-pesign-bridge/other-sigul-signing-key-passphrase
```

Finally, start the service:

```
sudo systemctl enable --now sigul-client-config.service
```

## Signing

With the service running, you can now use it to sign PE files:

```bash
pesign-client --sign \
    --token="signing-key" \
    --certificate="codesigning" \
    --infile=unsigned-application.efi \
    --outfile=signed-application.efi
```

The default setup requires that the user executing pesign-client be in the
`pesign` group.