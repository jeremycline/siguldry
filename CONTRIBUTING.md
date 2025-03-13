# Contribution Guide

Thanks for considering contributing to sigul-pesign-bridge, we really appreciate it!

## Development Setup

### Rust
To build and test this project, you will need a relatively recent version of
[Rust](https://www.rust-lang.org/). The current required version is documented
in the `Cargo.toml` file for each crate.

### System Dependencies

A few dependencies from your distribution are also required. This is expected to run on Fedora or RHEL,
although it may work elsewhere:

```bash
sudo dnf install pesign sbsigntools openssl-devel
```

Additionally, the CI is easiest to run with containers for the Sigul bridge and server:

```bash
sudo dnf install podman podman-compose
```

### Integration Tests

The integration tests use the Sigul server and Sigul bridge which can be tricky to set up. Fortunately,
there's a container image (built from `devel/Containerfile.sigul`) to make things easier. TLS certificates
for authenticating with the service as well as signing PE files are baked into the image. For convenience,
these are also checked into the repository at `devel/creds/` by running `cargo xtask extract-keys` whenever
a new image is built.

#### Running tests

Start the Sigul server and bridge by running the following from the repository root:

```bash
# Start the services
podman compose up -d
```

Now we can run the tests:

```bash
cargo test
```

## Licensing

Your commit messages must include a Signed-off-by tag with your name and e-mail
address, indicating that you agree to the [Developer Certificate of Origin](
https://developercertificate.org/) version 1.1:

    Developer Certificate of Origin
    Version 1.1

    Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

    Everyone is permitted to copy and distribute verbatim copies of this
    license document, but changing it is not allowed.

    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I
        have the right to submit it under the open source license
        indicated in the file; or

    (b) The contribution is based upon previous work that, to the best
        of my knowledge, is covered under an appropriate open source
        license and I have the right under that license to submit that
        work with modifications, whether created in whole or in part
        by me, under the same open source license (unless I am
        permitted to submit under a different license), as indicated
        in the file; or

    (c) The contribution was provided directly to me by some other
        person who certified (a), (b) or (c) and I have not modified
        it.

    (d) I understand and agree that this project and the contribution
        are public and that a record of the contribution (including all
        personal information I submit with it, including my sign-off) is
        maintained indefinitely and may be redistributed consistent with
        this project or the open source license(s) involved.

Use ``git commit -s`` to add the Signed-off-by tag.
