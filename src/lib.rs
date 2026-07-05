//! Cyberdrop API client.
//!
//! This crate provides a small, async wrapper around a subset of Cyberdrop's HTTP API.
//! It is built on [`reqwest`] and is intended to be copy-paste friendly in CLI tools and
//! simple services.
//!
//! ## Quickstart
//!
//! Authenticate, then call endpoints that require a token:
//!
//! ```no_run
//! use cyberdrop_client::CyberdropClient;
//! use std::path::Path;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), cyberdrop_client::CyberdropError> {
//! // 1) Create an unauthenticated client.
//! let client = CyberdropClient::new()?;
//!
//! // 2) Exchange credentials for a token.
//! let token = client.login("username", "password").await?;
//!
//! // 3) Use a cloned client that includes the token on authenticated requests.
//! let authed = client.with_auth_token(token.into_string());
//! let albums = authed.list_albums().await?;
//! println!("albums: {}", albums.len());
//!
//! // 4) Create an album and upload a file into it.
//! let album_id = authed
//!     .create_album("my uploads", Some("created by cyberdrop-client"))
//!     .await?;
//! let uploaded = authed
//!     .upload_file(Path::new("path/to/file.jpg"), Some(album_id))
//!     .await?;
//! println!("uploaded {} -> {}", uploaded.name, uploaded.url);
//! # Ok(())
//! # }
//! ```
//!
//! Note: `upload_file` streams smaller files and reads larger files in chunks.
//!
//! ## Authentication
//!
//! Authenticated endpoints use an HTTP header named `token` (not an `Authorization: Bearer ...`
//! header). Methods that *require* authentication return [`CyberdropError::MissingAuthToken`]
//! if no token is configured.
//!
//! ## Timeouts, Retries, Polling
//!
//! - **Timeouts:** The client uses a single 30 second *request* timeout. Timeout failures surface
//!   as [`CyberdropError::Http`] (from `reqwest`).
//! - **Retries:** This crate does not implement retries, backoff, or idempotency safeguards.
//!   If you need retries, add them at the call site.
//! - **Polling:** This crate does not poll for eventual consistency. Methods return once the HTTP
//!   request/response completes.
//!
//! ## Error Model
//!
//! Higher-level API methods (for example, [`CyberdropClient::list_albums`]) treat non-2xx HTTP
//! responses as errors:
//! - `401`/`403` become [`CyberdropError::AuthenticationFailed`]
//! - other non-2xx statuses become [`CyberdropError::RequestFailed`]
//!
//! External system failures are surfaced as:
//! - [`CyberdropError::Io`] when reading local files (for example, in [`CyberdropClient::upload_file`])
//! - [`CyberdropError::Http`] for network/transport failures (DNS, TLS, connection errors, timeouts)

mod account;
mod albums;
mod client;
mod config;
mod error;
mod files;
mod token;
mod uploads;

pub use account::{Permissions, TokenVerification};
pub use albums::{Album, AlbumFiles, EditAlbumResult};
pub use client::CyberdropClient;
pub use error::CyberdropError;
pub use files::AlbumFile;
pub use token::AuthToken;
pub use uploads::{UploadProgress, UploadedFile};
