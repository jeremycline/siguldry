# sigul-pesign-bridge
Bridge pesign-client requests to a Sigul server

# Integration test setup

This is a royal pain and could probably be easier. Steps for now:

```bash
mkdir ~/.sigul
cp devel/sigul-client.conf ~/.sigul/client.conf

podman compose up -d
podman cp siguldry_sigul-bridge_1:/var/lib/sigul/ ~/.sigul
# now vi /etc/hosts to have sigul-bridge resolve to localhost
# then:
./devel/sigul_key_setup.sh

# Set up a fake credentials directory like systemd
mkdir creds/
echo "my-signing-password" > creds/sigul-signing-key-passphrase

# Finally we can run the tests
CREDENTIALS_DIRECTORY=$(pwd)/creds/ cargo test
# Don't forget to remove the /etc/hosts entry or next time you bring up the compose the
# server won't resolve the sigul-bridge correctly
```

Messing around with hostname resolution is important because the certificates need
to match the hostname looked up.