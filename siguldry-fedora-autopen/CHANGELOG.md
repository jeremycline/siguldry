# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-08-06

### Added

- AMQP credentials can now be provided via systemd credentials (#217)

- A limit on the amount of storage used when signing RPMs has been added and
  can be configured with the `storage_limit_mb` setting in the `rpm` section
  (#217)

- Added a feature to re-sign a Koji tag with the specified key, which can be
  configured in the `resign_tags` setting to the `koji` section (#248)

### Changed

- RPMs are downloaded to `/var/tmp` by default, which is typically backed by
  durable storage instead of a RAM filesystem. This helps manage memory usage
  as `rpmsign` may use `/tmp` to make a copy of the RPMs, leading to rather
  large amounts of memory usage (#226)

### Fixed

- The systemd unit now includes an Install section (#214)

- The `rpms_signed` Prometheus metric now updates as RPMs complete rather than
  when all RPMs in the build complete (#217)

- Koji's `writeSignedRPM()` API is called prior to moving the build to the
  destination tag, matching robosignatory behavior (#217)

## [0.1.0] - 2026-05-26

### Added

- An AMQP consumer to automatically sign Koji-built RPMs, OSTree commits, and CoreOS Artifacts (#202)
