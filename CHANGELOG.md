# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4] - 2022-12-02

### Added

- Custom exceptions ImageNotFound, V2ImageNotFound, V1ImageNotFound, LayersNotFound

### Changed

- `arm64` and `arm64/v8` now properly matched

## [0.3] - 2022-08-08

### Added

- `--version` parameter

### Changed

- Improved `--help` usage
- More actionnable error message on incorrect image ref
- Fail on unsupported manifest instead of creating invalid tarball

## [0.2] – 2022-07-27

## Changed

- Destination folder created if non-existent
- Better error messages

## [0.1] – 2022-07-19

- initial release
