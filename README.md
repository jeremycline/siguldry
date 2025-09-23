# Siguldry

Tools and services to manage signing keys.

Heavily inspired by [Sigul](https://pagure.io/sigul), Siguldry provides a
server that manages a set of signing keys and can be configured to accept no
incoming network traffic, a bridge that proxies requests to the server, and a
client that request various types of signatures. It also offers a client that
impersonates the pesign daemon for signing UEFI applications via pesign-client.

Although this is primarily developed with Fedora in mind, there is nothing
Fedora-specific in the server, bridge, or client. Some tools included in this
repository are RPM-specific, but it is not a requirement.

## Development

### MSRV

The minimum supported Rust version tracks the latest toolchain available in
Enterprise Linux releases. For example, when RHEL 10.1 is released, the MSRV
may be bumped from 1.84 to 1.89.

### System Dependencies

In addition to its Rust dependencies, Siguldry requires the OpenSSL and SQLite
libraries.


### Test Dependencies

To run the test suite, you will need:

 - `pkcs11-tool` (provided by the `opensc` package on Fedora)
 - `softhsm2-util` (provided by `softhsm` on Fedora)
 - `openssl` (provided by `openssl` on Fedora)
 - `sq` (provided by `sequoia-sq` on Fedora)
 - `sqlite` and its development headers (provided by `sqlite-devel` on Fedora)
