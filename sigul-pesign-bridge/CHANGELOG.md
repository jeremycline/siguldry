# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

