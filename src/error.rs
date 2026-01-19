use reqwest::StatusCode;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CyberdropError {
    #[error("invalid url: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("authentication failed with status {0}")]
    AuthenticationFailed(StatusCode),
    #[error("auth token required for this request")]
    MissingAuthToken,
    #[error("login response missing token")]
    MissingToken,
    #[error("{0}")]
    MissingField(&'static str),
    #[error("folder already present: {0}")]
    AlbumAlreadyExists(String),
    #[error("api error: {0}")]
    Api(String),
    #[error("invalid file name")]
    InvalidFileName,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}
