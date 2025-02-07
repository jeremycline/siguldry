#!/bin/bash

# Create a new softhsm2 token, create some keys and certificates within the token
# and interact with them via NSS.
#
# In an EL9 environment:
#
# $ dnf install epel-release  # for sbsigntools
# $ dnf install softhsm opensc nss-tools openssl p11-kit openssl-pkcs11 sbsigntools
#
# This uses the deprecated OpenSSL engine interface since the pkcs11 provider isn't available
# in RHEL 9.

set -xeuo pipefail

HSM_PIN="abc123def"
HSM_SO_PIN="fed321cba"
TOKEN_LABEL="Sigul Token 0"

# Initialize a token slot in softhsm
softhsm2-util \
	--init-token --slot 0 --label "$TOKEN_LABEL" \
	--pin "$HSM_PIN" --so-pin "$HSM_SO_PIN"
SLOT_URI=$(p11-kit list-modules | grep "^\s*uri:.*token=Sigul" | awk '{ print $2 }')
# Make a keypair for a CA and for code signing
pkcs11-tool --module /usr/lib64/softhsm/libsofthsm.so \
	--login --pin "$HSM_PIN" \
	--keypairgen --label="Secure Boot CA" \
	--key-type rsa:2048 --usage-sig --id 1
pkcs11-tool --module /usr/lib64/softhsm/libsofthsm.so \
	--login --pin "$HSM_PIN" \
	--keypairgen --label="Secure Boot Code Signing" \
	--key-type rsa:2048 --usage-sig --id 2

# Generate certificates for the above key pairs
cat > openssl.cnf << EOF
[code_signing_exts]
keyUsage = digitalSignature
extendedKeyUsage = codeSigning
EOF
printf "%s\n" "$HSM_PIN" > hsm_pin
openssl req -passin file:./hsm_pin -new -x509 -days 3650 -sha256 -extensions v3_ca \
	-subj "/CN=Secure Boot CA" -engine pkcs11 -keyform engine \
	-key "${SLOT_URI};object=Secure%20Boot%20CA;type=private" \
	-out secure-boot-ca.pem
openssl req -passin file:./hsm_pin -config ./openssl.cnf -new -sha256 -extensions code_signing_exts \
	-subj "/CN=Secure Boot Code Signing" -engine pkcs11 -keyform engine \
	-key "${SLOT_URI};object=Secure%20Boot%20Code%20Signing;type=private" \
	-out secure-boot-code-signing.csr
openssl x509 -passin file:./hsm_pin -req -engine pkcs11 -CAkeyform engine \
	-in secure-boot-code-signing.csr \
	-extfile openssl.cnf -extensions code_signing_exts \
	-CAkey "${SLOT_URI};object=Secure%20Boot%20CA;type=private" \
	-CA ./secure-boot-ca.pem -days 365 -sha256 \
	-out secure-boot-code-signing.crt

# Do they seem reasonable?
openssl verify -CAfile secure-boot-ca.pem secure-boot-ca.pem
openssl verify -CAfile secure-boot-ca.pem secure-boot-code-signing.crt

# Write the certificates to the token
pkcs11-tool --module /usr/lib64/softhsm/libsofthsm.so \
	--login --pin "$HSM_PIN" \
	--write-object secure-boot-ca.pem \
	--type cert --label "Secure Boot CA Certificate" --id 1
pkcs11-tool --module /usr/lib64/softhsm/libsofthsm.so \
	--login --pin "$HSM_PIN" \
	--write-object secure-boot-code-signing.crt \
	--type cert --label "Secure Boot Code Signing Certificate" --id 2
