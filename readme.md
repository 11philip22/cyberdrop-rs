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

Rust API client for Cyberdrop, with async support and typed models. Works with both `cyberdrop.me` and `bunkr.cr`.

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
cyberdrop-client = "0.4.3"
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

Example: Bunkr (`dash.bunkr.cr`)

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

This project is licensed under the MIT License; see the [license](license) file for details.
