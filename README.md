<h1 align="center">cyberdrop-client</h1>

<p align="center">
  <a href="https://crates.io/crates/cyberdrop-client"><img src="https://img.shields.io/crates/v/cyberdrop-client?style=flat-square&logo=rust" alt="Crates.io"></a>
  <a href="https://docs.rs/cyberdrop-client"><img src="https://img.shields.io/docsrs/cyberdrop-client?style=flat-square&logo=docs.rs" alt="docs.rs"></a>
  <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/rust-2024-orange?style=flat-square&logo=rust" alt="Rust 2024"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#common-tasks">Common Tasks</a> •
  <a href="#api-surface">API Surface</a> •
  <a href="#development">Development</a> •
  <a href="#api-notes">API Notes</a>
</p>

---

Async Rust client for a focused subset of the [Cyberdrop](https://cyberdrop.cr) API.

It wraps the browser-facing Cyberdrop endpoints with typed models, explicit errors, and a small `reqwest`-based async surface suitable for CLI tools and simple services.

> [!NOTE]
> Cyberdrop is an external service and can change without notice. The notes in `docs/apis/` capture the API behavior observed while building this crate.

## Features

- Login, register, and token verification.
- Authenticated album listing, creation, metadata edits, and file pagination.
- Single-file uploads with automatic upload-node discovery.
- Streaming uploads for smaller files and chunked uploads for larger files.
- Optional upload progress callback.
- Typed error model for auth failures, missing tokens, missing fields, API errors, I/O errors, and HTTP transport failures.

## Installation

```toml
[dependencies]
cyberdrop-client = "0.5"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Quick Start

```rust
use cyberdrop_client::CyberdropClient;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), cyberdrop_client::CyberdropError> {
    let client = CyberdropClient::new()?;
    let token = client.login("username", "password").await?;

    let client = client.with_auth_token(token.into_string());

    let album_id = client
        .create_album("uploads from rust", Some("created by cyberdrop-client"))
        .await?;

    let uploaded = client
        .upload_file(Path::new("image.jpg"), Some(album_id))
        .await?;

    println!("uploaded {} -> {}", uploaded.name, uploaded.url);
    Ok(())
}
```

## Client Setup

Use `CyberdropClient::new()` for defaults, or the builder when you need a custom user agent, timeout, or initial token.

```rust
use cyberdrop_client::CyberdropClient;
use std::time::Duration;

let client = CyberdropClient::builder()
    .user_agent("my-tool/1.0")
    .timeout(Duration::from_secs(60))
    .auth_token("existing-token")
    .build()?;
```

Authenticated requests use Cyberdrop's `token` header, not `Authorization: Bearer`.

## Common Tasks

### Verify a token

```rust
let verification = client.verify_token("token-to-check").await?;
println!("{}: {}", verification.username, verification.success);
```

### List albums and files

```rust
let albums = client.list_albums().await?;

for album in albums {
    let files = client.list_album_files(album.id).await?;
    println!("{} has {} files", album.name, files.count);
}
```

Use `list_album_files_page(album_id, page)` when you want to control pagination yourself.

### Edit an album

```rust
let album = client.get_album_by_id(album_id).await?;

let edited = client
    .edit_album(
        album.id,
        "new name",
        album.description,
        album.download,
        album.public,
        false,
    )
    .await?;
```

Pass `true` as the last argument to request a new public link identifier.

### Track upload progress

```rust
let uploaded = client
    .upload_file_with_progress("video.mp4", Some(album_id), |progress| {
        println!(
            "{}: {}/{} bytes",
            progress.file_name, progress.bytes_sent, progress.total_bytes
        );
    })
    .await?;
```

## API Surface

| Area | Methods |
| --- | --- |
| Client | `new`, `builder`, `with_auth_token`, `auth_token` |
| Account | `login`, `register`, `verify_token` |
| Albums | `list_albums`, `get_album_by_id`, `create_album`, `edit_album` |
| Files | `list_album_files`, `list_album_files_page` |
| Uploads | `get_upload_url`, `upload_file`, `upload_file_with_progress` |

## Error Model

Higher-level methods convert non-success HTTP responses into `CyberdropError`:

- `401` and `403` become `AuthenticationFailed`.
- Other non-2xx statuses become `RequestFailed`.
- API-level failures become `Api`.
- Missing required response fields become `MissingField`.
- File reads become `Io`.
- Network, TLS, DNS, timeout, and response decode failures become `Http`.

## Development

```sh
cargo fmt
cargo check --all-features --all-targets
cargo test
```

Live tests are feature-gated because they create real Cyberdrop accounts, albums, and uploads:

```sh
cargo test --features live-tests
```

## API Notes

Endpoint research lives in [`docs/apis/`](docs/apis/):

- [`auth.md`](docs/apis/auth.md)
- [`albums.md`](docs/apis/albums.md)
- [`uploads.md`](docs/apis/uploads.md)
- [`public-files.md`](docs/apis/public-files.md)
- [`configuration.md`](docs/apis/configuration.md)

Use those files when extending the typed client surface.
