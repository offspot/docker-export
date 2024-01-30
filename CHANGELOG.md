# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2024-01-30

### Added

- `get_export_filename(image, platform)` for an fs-safe filename

### Changed

- `fs_name` now includes image reference and is filesystem safe for all OS.
- Default export filename now includes platform as well.

## [1.0.1] - 2023-08-11

### Changed

- Default-variant-safe `Platform` comparison (fixes linux/arm64/v8 not == linux/arm64)

## [1.0] - 2023-08-10

### Added

- `Image.exists()`/`image_exists()` function to check registry for an image+platform
- `Image.get_digest()`/`get_image_digest()` function to retrieve unique image+platform digest
- Proper type hints

### Changed

- Fixed Python 3.8 and 3.9 usage (was using 3.10+ specific feature)

### Removed

- Support for python 3.6 and 3.7 (both EOL)

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
