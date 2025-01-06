# sigul-pesign-bridge
Drop-in replacement for pesign's daemon that bridges pesign-client requests to a Sigul server.

# Integration test setup

This is a royal pain and could probably be easier. Steps for now:

```bash
# Prerequisites: dnf install sigul pesign

# This needs to be done whenever the CI container changes or the checked-in
# sigul client configuration changes.
mkdir ~/.sigul
cp devel/local/client.conf ~/.sigul/client.conf
podman pull quay.io/jeremycline/sigul-pesign-bridge-ci:latest && \
    podman run --name sigul-key-extract quay.io/jeremycline/sigul-pesign-bridge-ci:latest && \
    podman cp sigul-key-extract:/var/lib/sigul/ ~/.sigul && \
    podman rm sigul-key-extract

# Start the service and create signing keys. The signing keys
# must be recreated whenever the compose is destroyed.
podman compose up -d
./devel/sigul_key_setup.sh

# Finally we can run the tests.
# 
# Set up a fake credentials directory like systemd. The signing password is set in
# the sigul_key_setup.sh script and must match.
mkdir creds/
echo "my-signing-password" > creds/sigul-signing-key-passphrase
cp devel/local/client.conf creds/sigul-client-config
CREDENTIALS_DIRECTORY=$(pwd)/creds/ cargo test
```