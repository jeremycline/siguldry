#!/bin/bash

set -xeuo pipefail

# Create a CA, then sign three certificates for the server, bridge, and client respectively.
mkdir -p creds/
pushd creds

cat > openssl.cnf << EOF
[client_and_server_auth_ext]
keyUsage = digitalSignature
extendedKeyUsage = clientAuth,serverAuth
[client_auth_ext]
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
[server_auth_ext]
keyUsage = digitalSignature
extendedKeyUsage = serverAuth
EOF

# Create a CA used to sign the client certificates as well as the server and bridge server certificates
openssl genrsa -out sigul.ca.private_key.pem 2048
openssl req -x509 -new -nodes -key sigul.ca.private_key.pem -days 3650 -sha256 -extensions v3_ca -subj "/CN=Sigul CA" -out sigul.ca.certificate.pem

# Create keys and certificates for server, client, and bridge
openssl genrsa -out sigul.server.private_key.pem 2048
openssl genrsa -out sigul.bridge.private_key.pem 2048
openssl genrsa -out sigul.client.private_key.pem 2048
openssl req -config ./openssl.cnf -new -sha256 -extensions client_and_server_auth_ext -subj "/CN=sigul-server" -key sigul.server.private_key.pem -out server-cert.csr
openssl req -config ./openssl.cnf -new -sha256 -extensions server_auth_ext -subj "/CN=sigul-bridge" -key sigul.bridge.private_key.pem -out bridge-cert.csr
openssl req -config ./openssl.cnf -new -sha256 -extensions client_auth_ext -subj "/CN=sigul-client" -key sigul.client.private_key.pem -out client-cert.csr
openssl x509 -req -in server-cert.csr -extfile ./openssl.cnf -extensions client_and_server_auth_ext -CAkey sigul.ca.private_key.pem -CA sigul.ca.certificate.pem -days 3650 -sha256 -out sigul.server.certificate.pem
openssl x509 -req -in bridge-cert.csr -extfile ./openssl.cnf -extensions server_auth_ext -CAkey sigul.ca.private_key.pem -CA sigul.ca.certificate.pem -days 3650 -sha256 -out sigul.bridge.certificate.pem
openssl x509 -req -in client-cert.csr -extfile ./openssl.cnf -extensions client_auth_ext -CAkey sigul.ca.private_key.pem -CA sigul.ca.certificate.pem -days 3650 -sha256 -out sigul.client.certificate.pem

rm openssl.cnf sigul.ca.private_key.pem *.csr

openssl verify -CAfile ./sigul.ca.certificate.pem sigul.server.certificate.pem
openssl verify -CAfile ./sigul.ca.certificate.pem sigul.bridge.certificate.pem
openssl verify -CAfile ./sigul.ca.certificate.pem sigul.client.certificate.pem

popd
