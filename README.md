<p align="center">
  <img src="assets/cyberdrop-client-hero-banner.png" alt="cyberdrop-client hero pane" width="980">
</p>

<p align="center">
  <a href="https://crates.io/crates/cyberdrop-client"><img src="https://img.shields.io/badge/crates.io-cyberdrop--client-F59E0B?style=for-the-badge&logo=rust&logoColor=white" alt="Crates.io"></a>
  <a href="https://docs.rs/cyberdrop-client"><img src="https://img.shields.io/badge/docs.rs-cyberdrop--client-3B82F6?style=for-the-badge&logo=readthedocs&logoColor=white" alt="Documentation"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-8B5CF6?style=for-the-badge" alt="MIT License"></a>
  <a href="https://github.com/woldp001/guerrillamail-client-rs/pulls"><img src="https://img.shields.io/badge/PRs-Welcome-22C55E?style=for-the-badge" alt="PRs Welcome"></a>
</p>

<p align="center">
  <a href="#features">Features</a> · <a href="#installation">Installation</a> · <a href="#quick-start">Quick Start</a> · <a href="#running-the-cli-examples">Running the CLI Examples</a> · <a href="#documentation">Documentation</a> · <a href="#contributing">Contributing</a> · <a href="#support">Support</a> · <a href="#license">License</a>
</p>

---

<!-- <video src="https://cyberdrop.cr/images/logo-v-200-opt.mp4"
       width="300"
       autoplay
       muted
       loop
       playsinline>
</video> -->

A rust API client for Cyberdrop, with async support and typed models. Works with both `cyberdrop.cr` and `bunkr.cr`.

## Features
- Login/register + token verification, with permissions in the response.
- Full album management: list, create, edit metadata, toggle public/download, and rotate share links.
- Album file listing with built‑in pagination (single page or all pages).
- Uploads with automatic upload‑node discovery, streaming small files and chunked uploads for large files, plus per‑file progress
callbacks.
- Typed models and explicit error types (auth failures, album‑not‑found, album‑exists, missing fields).
- Optional low‑level get for endpoints not covered by higher‑level methods.

## Installation

```toml
[dependencies]
cyberdrop-client = "0.4.5"
```

## Quick Start

### Cyberdrop Example
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

### Bunkr Example

```rust
let client = CyberdropClient::builder()
    .base_url("https://dash.bunkr.cr")?
    .auth_token("your_auth_token_here")
    .timeout(std::time::Duration::from_secs(500))
    .build()?;
```

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

## Documentation

For detailed API documentation, visit [docs.rs/cyberdrop-client](https://docs.rs/cyberdrop-client).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Support

If this crate saves you time or helps your work, support is appreciated:

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/11philip22)

## License

This project is licensed under the MIT License; see the [license](https://opensource.org/licenses/MIT) for details.
