# AGENTS.md

Instructions for AI agents working on this repository.

## Project

`cyberdrop-client` — an async Rust HTTP client for the Cyberdrop and Bunkr APIs.

## Commands

```sh
cargo build              # compile
cargo test               # run unit tests (inline #[cfg(test)] modules)
cargo fmt --check        # verify formatting
cargo clippy -- -D warnings  # lint (warnings denied)
cargo run --example <name>   # run an example
```

All four checks (`build`, `test`, `fmt --check`, `clippy -- -D warnings`) must pass before considering work done.

## Structure

```
src/
  lib.rs       — crate root, re-exports
  client.rs    — CyberdropClient, builder, upload helpers, upload tests
  error.rs     — CyberdropError enum
  models.rs    — request/response types, typed models
  transport.rs — low-level HTTP transport, transport tests
examples/      — CLI examples (cargo run --example <name>)
```

## Conventions

- Rust edition 2024, MSRV not enforced.
- Private types use `pub(crate)`.
- Tests live in `#[cfg(test)] mod tests` blocks at the bottom of the source file.
- No integration test directory (`tests/`).
- No CI pipeline; agents must run all checks locally before finishing.
- Do not commit secrets, tokens, or credentials.
- Keep public API backward-compatible; changes should be additive.
