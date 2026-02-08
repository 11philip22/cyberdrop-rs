use std::{path::Path, time::Duration};

use reqwest::{multipart::Form, Client, ClientBuilder, Url};
use serde::Serialize;
use uuid::Uuid;

use crate::models::{
    AlbumsResponse, CreateAlbumRequest, CreateAlbumResponse, LoginRequest, LoginResponse,
    UploadResponse, VerifyTokenRequest, VerifyTokenResponse,
};
use crate::transport::Transport;
use crate::{AuthToken, AlbumsList, CyberdropError, TokenVerification, UploadedFile};

#[derive(Debug, Clone)]
pub(crate) struct ChunkFields {
    pub(crate) uuid: String,
    pub(crate) chunk_index: u64,
    pub(crate) total_size: u64,
    pub(crate) chunk_size: u64,
    pub(crate) total_chunks: u64,
    pub(crate) byte_offset: u64,
    pub(crate) file_name: String,
    pub(crate) mime_type: String,
    pub(crate) album_id: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct FinishFile {
    pub(crate) uuid: String,
    pub(crate) original: String,
    #[serde(rename = "type")]
    pub(crate) r#type: String,
    pub(crate) albumid: Option<u64>,
    pub(crate) filelength: Option<u64>,
    pub(crate) age: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct FinishChunksPayload {
    pub(crate) files: Vec<FinishFile>,
}

const CHUNK_SIZE: u64 = 95_000_000;
const DEFAULT_BASE_URL: &str = "https://cyberdrop.cr/";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Async HTTP client for a subset of Cyberdrop endpoints.
///
/// Most higher-level methods map non-2xx responses to [`CyberdropError`]. For raw access where
/// you want to inspect status codes and bodies directly, use [`CyberdropClient::get`].
#[derive(Debug, Clone)]
pub struct CyberdropClient {
    transport: Transport,
}

impl CyberdropClient {
    /// Build a client with a custom base URL.
    ///
    /// `base_url` is parsed as a [`Url`]. It is then used as the base for relative API paths via
    /// [`Url::join`], so a trailing slash is recommended.
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, CyberdropError> {
        CyberdropClientBuilder::new().base_url(base_url)?.build()
    }

    /// Start configuring a client with the crate's defaults.
    ///
    /// Defaults:
    /// - Base URL: `https://cyberdrop.cr/`
    /// - Timeout: 30 seconds
    /// - User agent: a browser-like UA string
    pub fn builder() -> CyberdropClientBuilder {
        CyberdropClientBuilder::new()
    }

    /// Current base URL.
    pub fn base_url(&self) -> &Url {
        self.transport.base_url()
    }

    /// Current auth token if configured.
    pub fn auth_token(&self) -> Option<&str> {
        self.transport.auth_token()
    }

    /// Return a clone of this client that applies authentication to requests.
    ///
    /// The token is attached as an HTTP header named `token`.
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.transport = self.transport.with_auth_token(token);
        self
    }

    /// Execute a GET request against a relative path on the configured base URL.
    ///
    /// This method returns the raw [`reqwest::Response`] and does **not** convert non-2xx status
    /// codes into errors. If a token is configured, it will be attached, but authentication is
    /// not required.
    ///
    /// # Errors
    ///
    /// Returns [`CyberdropError::Http`] on transport failures (including timeouts). This method
    /// does not map HTTP status codes to [`CyberdropError`] variants.
    pub async fn get(&self, path: impl AsRef<str>) -> Result<reqwest::Response, CyberdropError> {
        self.transport.get_raw(path.as_ref()).await
    }

    /// Authenticate and retrieve a token.
    ///
    /// The returned token can be installed on a client via [`CyberdropClient::with_auth_token`]
    /// or [`CyberdropClientBuilder::auth_token`].
    ///
    /// # Errors
    ///
    /// - [`CyberdropError::AuthenticationFailed`] / [`CyberdropError::RequestFailed`] for non-2xx statuses
    /// - [`CyberdropError::MissingToken`] if the response body omits the token field
    /// - [`CyberdropError::Http`] for transport failures (including timeouts)
    pub async fn login(
        &self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<AuthToken, CyberdropError> {
        let payload = LoginRequest {
            username: username.into(),
            password: password.into(),
        };

        let response: LoginResponse = self.transport.post_json("api/login", &payload, false).await?;

        AuthToken::try_from(response)
    }

    /// Verify a token and fetch associated permissions.
    ///
    /// This request does not require the client to be authenticated; the token to verify is
    /// supplied in the request body.
    ///
    /// # Errors
    ///
    /// - [`CyberdropError::AuthenticationFailed`] / [`CyberdropError::RequestFailed`] for non-2xx statuses
    /// - [`CyberdropError::MissingField`] if expected fields are missing in the response body
    /// - [`CyberdropError::Http`] for transport failures (including timeouts)
    pub async fn verify_token(
        &self,
        token: impl Into<String>,
    ) -> Result<TokenVerification, CyberdropError> {
        let payload = VerifyTokenRequest { token: token.into() };

        let response: VerifyTokenResponse =
            self.transport.post_json("api/tokens/verify", &payload, false).await?;

        TokenVerification::try_from(response)
    }

    /// List albums for the authenticated user.
    ///
    /// Requires an auth token (see [`CyberdropClient::with_auth_token`]).
    ///
    /// # Errors
    ///
    /// - [`CyberdropError::MissingAuthToken`] if the client has no configured token
    /// - [`CyberdropError::AuthenticationFailed`] / [`CyberdropError::RequestFailed`] for non-2xx statuses
    /// - [`CyberdropError::MissingField`] if expected fields are missing in the response body
    /// - [`CyberdropError::Http`] for transport failures (including timeouts)
    pub async fn list_albums(&self) -> Result<AlbumsList, CyberdropError> {
        let response: AlbumsResponse = self.transport.get_json("api/albums", true).await?;
        AlbumsList::try_from(response)
    }

    /// Create a new album and return its numeric ID.
    ///
    /// Requires an auth token. If the service reports that an album with a similar name already
    /// exists, this returns [`CyberdropError::AlbumAlreadyExists`].
    ///
    /// # Errors
    ///
    /// - [`CyberdropError::MissingAuthToken`] if the client has no configured token
    /// - [`CyberdropError::AuthenticationFailed`] / [`CyberdropError::RequestFailed`] for non-2xx statuses
    /// - [`CyberdropError::AlbumAlreadyExists`] if the service indicates an album already exists
    /// - [`CyberdropError::Api`] for other service-reported failures
    /// - [`CyberdropError::MissingField`] if expected fields are missing in the response body
    /// - [`CyberdropError::Http`] for transport failures (including timeouts)
    pub async fn create_album(
        &self,
        name: impl Into<String>,
        description: Option<impl Into<String>>,
    ) -> Result<u64, CyberdropError> {
        let payload = CreateAlbumRequest {
            name: name.into(),
            description: description.map(Into::into),
        };

        let response: CreateAlbumResponse = self.transport.post_json("api/albums", &payload, true).await?;

        u64::try_from(response)
    }

    /// Upload a single file.
    ///
    /// Requires an auth token.
    ///
    /// Implementation notes:
    /// - The file is currently read fully into memory before uploading.
    /// - Files larger than `95_000_000` bytes are uploaded in chunks.
    /// - If `album_id` is provided, it is sent as an `albumid` header on the chunk/single-upload
    ///   requests and included in the `finishchunks` payload.
    ///
    /// # Errors
    ///
    /// - [`CyberdropError::MissingAuthToken`] if the client has no configured token
    /// - [`CyberdropError::InvalidFileName`] if `file_path` does not have a valid UTF-8 file name
    /// - [`CyberdropError::Io`] if reading the file fails
    /// - [`CyberdropError::AuthenticationFailed`] / [`CyberdropError::RequestFailed`] for non-2xx statuses
    /// - [`CyberdropError::Api`] if the service reports an upload failure (including per-chunk failures)
    /// - [`CyberdropError::MissingField`] if expected fields are missing in the response body
    /// - [`CyberdropError::Http`] for transport failures (including timeouts)
    pub async fn upload_file(
        &self,
        file_path: impl AsRef<Path>,
        album_id: Option<u64>,
    ) -> Result<UploadedFile, CyberdropError> {
        let file_path = file_path.as_ref();
        let file_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(CyberdropError::InvalidFileName)?
            .to_string();

        let mime = mime_guess::from_path(file_path)
            .first_raw()
            .unwrap_or("application/octet-stream")
            .to_string();

        let data = std::fs::read(file_path)?;
        let total_size = data.len() as u64;

        // For small files, use the simple single-upload endpoint.
        if total_size <= CHUNK_SIZE {
            let part = reqwest::multipart::Part::bytes(data).file_name(file_name.clone());
            let part = match part.mime_str(&mime) {
                Ok(p) => p,
                Err(_) => reqwest::multipart::Part::bytes(Vec::new()).file_name(file_name.clone()),
            };
            let form = Form::new().part("files[]", part);
            let response: UploadResponse = self
                .transport
                .post_single_upload("api/upload", form, album_id)
                .await?;
            return UploadedFile::try_from(response);
        }

        let chunk_size = CHUNK_SIZE.min(total_size.max(1));
        let total_chunks = ((total_size + chunk_size - 1) / chunk_size).max(1);
        let uuid = Uuid::new_v4().to_string();

        for (index, chunk) in data.chunks(chunk_size as usize).enumerate() {
            let chunk_index = index as u64;
            let byte_offset = chunk_index * chunk_size;

            let response: serde_json::Value = self
                .transport
                .post_chunk(
                    "api/upload",
                    chunk.to_vec(),
                    ChunkFields {
                        uuid: uuid.clone(),
                        chunk_index,
                        total_size,
                        chunk_size,
                        total_chunks,
                        byte_offset,
                        file_name: file_name.clone(),
                        mime_type: mime.clone(),
                        album_id,
                    },
                )
                .await?;

            if !response.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                return Err(CyberdropError::Api(format!("chunk {} failed", chunk_index)));
            }
        }

        let payload = FinishChunksPayload {
            files: vec![FinishFile {
                uuid,
                original: file_name,
                r#type: mime,
                albumid: album_id,
                filelength: None,
                age: None,
            }],
        };

        let response: UploadResponse = self
            .transport
            .post_json_with_upload_headers("api/upload/finishchunks", &payload)
            .await?;

        UploadedFile::try_from(response)
    }
}

/// Builder for [`CyberdropClient`].
#[derive(Debug)]
pub struct CyberdropClientBuilder {
    base_url: Option<Url>,
    user_agent: Option<String>,
    timeout: Duration,
    auth_token: Option<AuthToken>,
    builder: ClientBuilder,
}

impl CyberdropClientBuilder {
    /// Create a new builder using the crate defaults.
    ///
    /// This is equivalent to [`CyberdropClient::builder`].
    pub fn new() -> Self {
        Self {
            base_url: None,
            user_agent: None,
            timeout: DEFAULT_TIMEOUT,
            auth_token: None,
            builder: Client::builder(),
        }
    }

    /// Override the base URL used for requests.
    pub fn base_url(mut self, base_url: impl AsRef<str>) -> Result<Self, CyberdropError> {
        self.base_url = Some(Url::parse(base_url.as_ref())?);
        Ok(self)
    }

    /// Set a custom user agent header.
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Provide an auth token that will be sent as bearer auth.
    pub fn auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(AuthToken::new(token));
        self
    }

    /// Configure the request timeout.
    ///
    /// This sets [`reqwest::ClientBuilder::timeout`], which applies a single deadline per request.
    /// Timeout failures surface as [`CyberdropError::Http`].
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Build a [`CyberdropClient`].
    ///
    /// If no base URL is configured, this uses `https://cyberdrop.cr/`.
    /// If no user agent is configured, a browser-like UA string is used.
    pub fn build(self) -> Result<CyberdropClient, CyberdropError> {
        let base_url = match self.base_url {
            Some(url) => url,
            None => Url::parse(DEFAULT_BASE_URL)?,
        };

        let mut builder = self.builder.timeout(self.timeout);
        builder = builder.user_agent(self.user_agent.unwrap_or_else(default_user_agent));

        let client = builder.build()?;

        Ok(CyberdropClient {
            transport: Transport::new(client, base_url, self.auth_token),
        })
    }
}

fn default_user_agent() -> String {
    // Match a browser UA; the service appears to expect browser-like clients.
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_carries_auth_token_into_client() {
        let client = CyberdropClient::builder()
            .auth_token("abc123")
            .build()
            .unwrap();

        assert_eq!(client.auth_token(), Some("abc123"));
    }

    #[tokio::test]
    async fn list_albums_requires_auth_token() {
        let client = CyberdropClient::builder().build().unwrap();
        let err = client.list_albums().await.unwrap_err();
        assert!(matches!(err, CyberdropError::MissingAuthToken));
    }

    #[tokio::test]
    async fn create_album_requires_auth_token() {
        let client = CyberdropClient::builder().build().unwrap();
        let err = client.create_album("name", None::<String>).await.unwrap_err();
        assert!(matches!(err, CyberdropError::MissingAuthToken));
    }
}
