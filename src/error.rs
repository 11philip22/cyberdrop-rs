use reqwest::StatusCode;
use thiserror::Error;

/// Errors returned by this crate.
///
/// This type includes HTTP status classification (authentication vs other failures), conversion
/// errors from loosely-typed API responses, and underlying I/O / HTTP client errors.
///
/// Notes:
/// - Network/transport failures (including timeouts) are returned as [`CyberdropError::Http`].
/// - Many API responses contain optional fields; missing required fields are reported as
///   [`CyberdropError::MissingField`].
#[derive(Debug, Error)]
pub enum CyberdropError {
    /// An invalid URL was provided or returned.
    #[error("invalid url: {0}")]
    InvalidUrl(#[from] url::ParseError),
    /// The server returned `401 Unauthorized` or `403 Forbidden`.
    #[error("authentication failed with status {0}")]
    AuthenticationFailed(StatusCode),
    /// A request completed but returned a non-success HTTP status (other than `401`/`403`).
    #[error("request failed with status {0}")]
    RequestFailed(StatusCode),
    /// An endpoint requiring authentication was called without configuring a token.
    #[error("auth token required for this request")]
    MissingAuthToken,
    /// The login response did not include a token.
    #[error("response missing token")]
    MissingToken,
    /// A required field was missing in an API response body.
    #[error("{0}")]
    MissingField(&'static str),
    /// The service indicates an album already exists (as interpreted by this crate).
    #[error("folder already present: {0}")]
    AlbumAlreadyExists(String),
    /// Requested album ID was not present in the authenticated user's album list.
    #[error("album not found: {0}")]
    AlbumNotFound(u64),
    /// The API returned an error message or an unexpected response shape.
    #[error("api error: {0}")]
    Api(String),
    /// The provided file path did not yield a valid UTF-8 file name.
    #[error("invalid file name")]
    InvalidFileName,
    /// An underlying I/O operation failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// An underlying HTTP client operation failed.
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}
