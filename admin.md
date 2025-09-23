# Admin Guide

The server side of Siguldry is made up of two components. The server itself,
and a proxy called the bridge. These communicate using mutual TLS (mTLS). The
client communicates with the bridge, also via mTLS.

This guide is written with the expectation that systemd is the service manager.

## Prereqs

In production, Siguldry should be run on three separate hosts.

Ideally, the server should be configured to drop all incoming connections and
should be managed out of band (e.g. through a management console, in person,
etc).

The bridge should be configured to accept connections on the two ports it
listens on. The server port should only accept connections from the server, and
ideally the client port should also be restricted to a set of known clients.

Clients have no special requirements, but are expected to be running in a trusted
environment.

In a test environment, all three services can run on the same host, or the server
and bridge can be on the same host.

## Certificates

If you already have a way to issue TLS certificates, it is perfectly fine to
use that. The following example generates a complete set of certificates for
those who do not, and is useful as a reference.

In all examples, adjust the common name to match your environment.

### Certificate Authority

First, create a certificate authority which is used to sign all our certificates:
```bash
openssl req -x509 -new -nodes -sha256 \
    -days 3650 \
    -extensions v3_ca \
    -subj "/CN=Siguldry CA" \
    -newkey rsa:4096 \
    -keyout siguldry.ca.private_key.pem \
    -out siguldry.ca.certificate.pem
```

Once you've finished signing everything you should store the private key in a safe
place or just delete it.


### Server

The server uses its certificate both as a client connecting to the bridge, and
as a server the client connects to via the bridge. The certificate for the
server must have the `clientAuth` _and_ `serverAuth` extended key usage
extensions.

Since the client only communicates through the bridge, and because the server
initiates the connection to the bridge, the server's name does not need to
resolve, but it does need to match what the client has been configured to
accept.

```bash
SERVER_CN="server.example.com"

openssl req -new -nodes -sha256 \
    -addext "subjectAltName = DNS:$SERVER_CN" \
    -addext "extendedKeyUsage = clientAuth,serverAuth" \
    -subj "/CN=$SERVER_CN" \
    -newkey rsa:4096 \
    -keyout siguldry.server.private_key.pem \
    -out server-cert.csr
openssl x509 -req -in server-cert.csr \
    -CAkey siguldry.ca.private_key.pem \
    -CA siguldry.ca.certificate.pem \
    -copy_extensions copyall \
    -days 3650 \
    -sha256 \
    -out siguldry.server.certificate.pem
```

### Bridge

The bridge accepts connections from the server and the client. It needs the
`serverAuth` extended key usage extension, and its name must resolve for both
the client and server.

```bash
BRIDGE_CN="bridge.example.com"

openssl req -new -nodes -sha256 \
    -addext "subjectAltName = DNS:$BRIDGE_CN" \
    -addext "extendedKeyUsage = serverAuth" \
    -subj "/CN=$BRIDGE_CN" \
    -newkey rsa:4096 \
    -keyout siguldry.bridge.private_key.pem \
    -out bridge-cert.csr
openssl x509 -req -in bridge-cert.csr \
    -CAkey siguldry.ca.private_key.pem \
    -CA siguldry.ca.certificate.pem \
    -copy_extensions copyall \
    -days 3650 \
    -sha256 \
    -out siguldry.bridge.certificate.pem
```

### Clients

Each client needs a certificate to authenticate with. The common name of the
certificate must match the username that we create on the Siguldry server later.

```bash
CLIENT_CN = "demo-client"

# Create and sign a client certificate
openssl req -new -nodes -sha256 \
    -addext "extendedKeyUsage = clientAuth" \
    -subj "/CN=$CLIENT_CN" \
    -newkey rsa:4096 \
    -keyout siguldry.client.private_key.pem \
    -out client-cert.csr
openssl x509 -req -in client-cert.csr \
    -CAkey siguldry.ca.private_key.pem \
    -CA siguldry.ca.certificate.pem \
    -copy_extensions copyall \
    -days 3650 \
    -sha256 \
    -out siguldry.client.certificate.pem
```

## Server Configuration

With the certificates in hand, we can configure the server. First, encrypt the server's
private key using systemd-creds and add the certificate to the credential store:

```bash
systemd-creds encrypt siguldry.server.private_key.pem /etc/credstore.encrypted/siguldry.server.private_key.pem
cp siguldry.server.certificate.pem /etc/credstore/
cp siguldry.ca.certificate.pem /etc/credstore/
```

Next, write a server config

