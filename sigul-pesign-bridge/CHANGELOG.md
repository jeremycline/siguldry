# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-03-13

### Changed

- The Python sigul client dependency has been replaced with the siguldry library (#26)

### Added

- It's possible to provide the `--credentials-directory` argument to the `config`
  sub-command to validate the files exist (#26).


## [0.2.1] - 2025-01-31

### Added

- An example configuration file (#24)

- The CLI manual page is now pre-built and checked into the repository (#23)

### Changed

- CI jobs now run with a restrictive set of default permissions (#22)


## [0.2.0] - 2025-01-16

### Added

- A changelog file.

- A cargo xtask to generate a manual page (#13).

- Two new CLI arguments which were previously undocumented environment variables:
  the `--log-filter` option is available on the root command and can also be specified
  with the `SIGUL_PESIGN_BRIDGE_LOG` environment variable. The `--credentials-directory`
  option is available on the `listen` sub-command and can be specified with the
  `CREDENTIALS_DIRECTORY` environment variable (#20).

### Changed

- The config sub-command no longer checks that the configured secret files exist (#20).

- Invalid log configuration will cause the service to exit rather than being silently
  ignored (#12).

- The systemd unit now uses `ImportCredential=`, recommends storing secrets in
  `/etc/credstore.encrypted`, and recommends more idiomatic secret names (#15).

### Fixed

- Clarified the configuration documentation by explicitly noting what the Sigul
  configuration is (#17).

- The `request_timeout_secs` configuration now works as documented (#19).

