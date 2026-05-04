# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Added focused upload helper tests covering upload strategy selection, chunk planning, chunk field construction, finish-chunks payload construction, finish URL generation, and invalid filename handling.

### Changed
- Split `upload_file_with_progress` into focused helpers for file preparation, single-file uploads, chunked uploads, and finish-chunks finalization to make upload behavior easier to review and maintain.
- Added a `Default` implementation for `CyberdropClientBuilder` and cleaned up minor clippy-reported code patterns.

## [0.4.6] - 2026-05-04

### Added
- Initial changelog entry for the existing Cyberdrop client crate.

[unreleased]: https://github.com/11philip22/cyberdrop-rs/compare/v0.4.6...HEAD
[0.4.6]: https://github.com/11philip22/cyberdrop-rs/releases/tag/v0.4.6
