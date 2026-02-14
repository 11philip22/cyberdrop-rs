# cyberdrop-client

[![Crates.io](https://img.shields.io/crates/v/cyberdrop-client.svg)](https://crates.io/crates/cyberdrop-client)
[![Documentation](https://docs.rs/cyberdrop-client/badge.svg)](https://docs.rs/cyberdrop-client)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/woldp001/guerrillamail-client-rs/pulls)

<video src="https://cyberdrop.cr/images/logo-v-200-opt.mp4"
       width="300"
       autoplay
       muted
       loop
       playsinline>
</video>

Rust API client for Cyberdrop, with async support and typed models.

## Features
- Async client built on `reqwest` (rustls TLS, no native OpenSSL requirement).
- Token-based authentication helpers (`login`, `with_auth_token`, `verify_token`).
- Typed models for common endpoints (albums, files, uploads).
- Upload support via multipart, including chunked uploads for large files.
- Configurable base URL, user-agent, and request timeout via `CyberdropClientBuilder`.

## Usage as Library
Add the crate:

```toml
[dependencies]
cyberdrop-client = "0.1"
```

Quickstart:

```rust
use cyberdrop_client::CyberdropClient;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), cyberdrop_client::CyberdropError> {
    let client = CyberdropClient::builder().build()?;
    let token = client.login("username", "password").await?;

    let authed = client.with_auth_token(token.into_string());
    let albums = authed.list_albums().await?;
    println!("albums: {}", albums.albums.len());

    let album_id = authed
        .create_album("my uploads", Some("created by cyberdrop-client"))
        .await?;
    let uploaded = authed
        .upload_file(Path::new("path/to/file.jpg"), Some(album_id))
        .await?;
    println!("uploaded {} -> {}", uploaded.name, uploaded.url);
    Ok(())
}
```

## Public API
- Client: `CyberdropClient`, `CyberdropClientBuilder`
- Errors: `CyberdropError`
- Models: `AuthToken`, `TokenVerification`, `Permissions`, `AlbumsList`, `Album`, `AlbumFilesPage`, `AlbumFile`, `UploadedFile`, `EditAlbumResult`

Common entrypoints on `CyberdropClient`:
- Auth: `register`, `login`, `verify_token`, `with_auth_token`
- Albums: `list_albums`, `create_album`, `edit_album`, `request_new_album_link`
- Album files: `list_album_files`
- Uploads: `upload_file`
- Low-level: `get` (returns raw `reqwest::Response` and does not treat non-2xx as errors)

## Running the CLI Examples
Examples live in `examples/` and can take args or environment variables.

Environment variables used by most examples:
- `CYBERDROP_USERNAME`
- `CYBERDROP_PASSWORD`

Run:

```sh
cargo run --example register -- <username> <password>
cargo run --example login -- <username> <password>
cargo run --example list_albums -- <username> <password>
cargo run --example create_album -- <username> <password> "<name>" ["<description>"]
cargo run --example edit_album -- <username> <password> <album_id> ["<new_name>"] ["<new_identifier>"]
cargo run --example list_album_files -- <username> <password> <album_id> [page]
cargo run --example request_new_album_link -- <username> <password> <album_id>
cargo run --example upload_file -- <username> <password> <path> [album_id]
```

## Contributing

PRs are welcome!  
Please run `cargo fmt` and `cargo clippy` before submitting.

If you’re changing behavior (e.g. stricter parsing), document it in the PR.

## Support

If this crate saves you time or helps your work, support is appreciated:

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/11philip22)

## License

This project is licensed under the MIT License; see the [license](license) file for details.
