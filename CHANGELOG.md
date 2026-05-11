# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-05-11

### Added
- Added focused upload helper tests covering upload strategy selection, chunk planning, chunk field construction, finish-chunks payload construction, finish URL generation, and invalid filename handling.

### Changed
- Split `upload_file_with_progress` into focused helpers for file preparation, single-file uploads, chunked uploads, and finish-chunks finalization to make upload behavior easier to review and maintain.
- Added a `Default` implementation for `CyberdropClientBuilder` and cleaned up minor clippy-reported code patterns.

### Fixed
- Upload `Origin` and `Referer` headers are now derived from the configured base URL instead of being hardcoded to `cyberdrop.cr`, fixing uploads against non-default hosts like Bunkr.
- Wrapped bare `matches!` calls in `assert!` in transport tests so they actually verify error variants.
- Chunked uploads now reuse a buffer via `Vec::with_capacity` and `read_buf` instead of allocating and zero-filling a new buffer per chunk, reducing allocator churn during large-file uploads.

## [0.4.6] - 2026-05-04

### Added
- Initial changelog entry for the existing Cyberdrop client crate.

[unreleased]: https://github.com/11philip22/cyberdrop-rs/compare/v0.4.6...HEAD
[0.4.6]: https://github.com/11philip22/cyberdrop-rs/releases/tag/v0.4.6
