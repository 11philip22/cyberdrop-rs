use std::{path::Path, time::Duration};

use bytes::Bytes;
use futures_core::Stream;
use reqwest::{Body, Client, ClientBuilder, Url, multipart::Form};
use serde::Serialize;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::models::{
    AlbumFilesPage, AlbumFilesResponse, AlbumsResponse, CreateAlbumRequest, CreateAlbumResponse,
    EditAlbumRequest, EditAlbumResponse, LoginRequest, LoginResponse, NodeResponse,
    RegisterRequest, RegisterResponse, UploadProgress, UploadResponse, VerifyTokenRequest,
    VerifyTokenResponse,
};
use crate::transport::Transport;
use crate::{
    AlbumsList, AuthToken, CyberdropError, EditAlbumResult, TokenVerification, UploadedFile,
};

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

struct ProgressStream<S, F> {
    inner: S,
    bytes_sent: u64,
    total_bytes: u64,
    file_name: String,
    callback: F,
}

impl<S, F> ProgressStream<S, F>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Unpin,
    F: FnMut(UploadProgress) + Send,
{
    fn new(inner: S, total_bytes: u64, file_name: String, callback: F) -> Self {
        Self {
            inner,
            bytes_sent: 0,
            total_bytes,
            file_name,
            callback,
        }
    }
}

impl<S, F> Stream for ProgressStream<S, F>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Unpin,
    F: FnMut(UploadProgress) + Send,
{
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                this.bytes_sent = this.bytes_sent.saturating_add(bytes.len() as u64);
                (this.callback)(UploadProgress {
                    file_name: this.file_name.clone(),
                    bytes_sent: this.bytes_sent,
                    total_bytes: this.total_bytes,
                });
                Poll::Ready(Some(Ok(bytes)))
            }
            other => other,
        }
    }
}

impl<S, F> Unpin for ProgressStream<S, F>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Unpin,
    F: FnMut(UploadProgress) + Send,
{
}

struct PreparedUpload {
    file: File,
    file_name: String,
    mime: String,
    total_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadStrategy {
    Single,
    Chunked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChunkUploadPlan {
    chunk_size: u64,
    total_chunks: u64,
}

impl ChunkUploadPlan {
    fn new(total_size: u64) -> Self {
        let chunk_size = CHUNK_SIZE.min(total_size.max(1));
        let total_chunks = total_size.div_ceil(chunk_size).max(1);

        Self {
            chunk_size,
            total_chunks,
        }
    }

    fn byte_offset(self, chunk_index: u64) -> u64 {
        chunk_index * self.chunk_size
    }
}

async fn prepare_upload_file(file_path: &Path) -> Result<PreparedUpload, CyberdropError> {
    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(CyberdropError::InvalidFileName)?
        .to_string();

    let mime = mime_guess::from_path(file_path)
        .first_raw()
        .unwrap_or("application/octet-stream")
        .to_string();

    let file = File::open(file_path).await?;
    let total_size = file.metadata().await?.len();

    Ok(PreparedUpload {
        file,
        file_name,
        mime,
        total_size,
    })
}

fn select_upload_strategy(total_size: u64) -> UploadStrategy {
    if total_size <= CHUNK_SIZE {
        UploadStrategy::Single
    } else {
        UploadStrategy::Chunked
    }
}

fn build_chunk_fields(
    uuid: &str,
    chunk_index: u64,
    plan: ChunkUploadPlan,
    total_size: u64,
    file_name: &str,
    mime_type: &str,
    album_id: Option<u64>,
) -> ChunkFields {
    ChunkFields {
        uuid: uuid.to_string(),
        chunk_index,
        total_size,
        chunk_size: plan.chunk_size,
        total_chunks: plan.total_chunks,
        byte_offset: plan.byte_offset(chunk_index),
        file_name: file_name.to_string(),
        mime_type: mime_type.to_string(),
        album_id,
    }
}

fn build_finish_chunks_payload(
    uuid: String,
    file_name: String,
    mime: String,
    album_id: Option<u64>,
) -> FinishChunksPayload {
    FinishChunksPayload {
        files: vec![FinishFile {
            uuid,
            original: file_name,
            r#type: mime,
            albumid: album_id,
            filelength: None,
            age: None,
        }],
    }
}

fn finish_chunks_url(mut upload_url: Url) -> Url {
    upload_url.set_path("/api/upload/finishchunks");
    upload_url
}

/// Async HTTP client for a subset of Cyberdrop endpoints.
///
/// Most higher-level methods map non-2xx responses to [`CyberdropError`]. For raw access where
/// you want to inspect status codes and bodies directly, use [`CyberdropClient::get`].
#[derive(Debug, Clone)]
pub struct CyberdropClient {
    transport: Transport,
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

const CHUNK_SIZE: u64 = 95_000_000;
const DEFAULT_BASE_URL: &str = "https://cyberdrop.cr/";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

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

    pub async fn get_album_by_id(
        &self,
        album_id: u64,
    ) -> Result<crate::models::Album, CyberdropError> {
        let albums = self.list_albums().await?;
        albums
            .albums
            .into_iter()
            .find(|album| album.id == album_id)
            .ok_or(CyberdropError::AlbumNotFound(album_id))
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

        let response: LoginResponse = self
            .transport
            .post_json("api/login", &payload, false)
            .await?;

        AuthToken::try_from(response)
    }

    /// Register a new account and retrieve a token.
    ///
    /// The returned token can be installed on a client via [`CyberdropClient::with_auth_token`]
    /// or [`CyberdropClientBuilder::auth_token`].
    ///
    /// Note: the API returns HTTP 200 even for validation failures; this method converts
    /// `{"success":false,...}` responses into [`CyberdropError::Api`].
    ///
    /// # Errors
    ///
    /// - [`CyberdropError::Api`] if the API reports a validation failure (e.g. username taken)
    /// - [`CyberdropError::MissingToken`] if the response body omits the token field on success
    /// - [`CyberdropError::Http`] for transport failures (including timeouts)
    pub async fn register(
        &self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<AuthToken, CyberdropError> {
        let payload = RegisterRequest {
            username: username.into(),
            password: password.into(),
        };

        let response: RegisterResponse = self
            .transport
            .post_json("api/register", &payload, false)
            .await?;

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
        let payload = VerifyTokenRequest {
            token: token.into(),
        };

        let response: VerifyTokenResponse = self
            .transport
            .post_json("api/tokens/verify", &payload, false)
            .await?;

        TokenVerification::try_from(response)
    }

    /// Fetch the upload node URL for the authenticated user.
    ///
    /// Requires an auth token (see [`CyberdropClient::with_auth_token`]).
    pub async fn get_upload_url(&self) -> Result<Url, CyberdropError> {
        let response: NodeResponse = self.transport.get_json("api/node", true).await?;

        if !response.success.unwrap_or(false) {
            let msg = response
                .description
                .or(response.message)
                .unwrap_or_else(|| "failed to fetch upload node".to_string());
            return Err(CyberdropError::Api(msg));
        }

        let url = response
            .url
            .ok_or(CyberdropError::MissingField("node response missing url"))?;

        Ok(Url::parse(&url)?)
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
        let response: AlbumsResponse = self
            .transport
            .get_json_with_header("api/albums", true, "Simple", "1")
            .await?;
        AlbumsList::try_from(response)
    }

    /// List all files in an album ("folder") by iterating pages until exhaustion.
    ///
    /// This calls [`CyberdropClient::list_album_files_page`] repeatedly starting at `page = 0` and
    /// stops when:
    /// - enough files have been collected to satisfy the API-reported `count`, or
    /// - a page returns zero files, or
    /// - a page yields no new file IDs (defensive infinite-loop guard).
    ///
    /// Requires an auth token (see [`CyberdropClient::with_auth_token`]).
    ///
    /// # Returns
    ///
    /// An [`AlbumFilesPage`] containing all collected files. The returned `count` is the total
    /// file count as reported by the API.
    ///
    /// # Errors
    ///
    /// Any error returned by [`CyberdropClient::list_album_files_page`].
    pub async fn list_album_files(&self, album_id: u64) -> Result<AlbumFilesPage, CyberdropError> {
        let mut page = 0u64;
        let mut all_files = Vec::new();
        let mut total_count = None::<u64>;
        let mut albums = std::collections::HashMap::new();
        let mut base_domain = None::<Url>;
        let mut seen = std::collections::HashSet::<u64>::new();

        loop {
            let res = self.list_album_files_page(album_id, page).await?;

            if base_domain.is_none() {
                base_domain = res.base_domain.clone();
            }
            if total_count.is_none() {
                total_count = Some(res.count);
            }
            albums.extend(res.albums.into_iter());

            if res.files.is_empty() {
                break;
            }

            let mut added = 0usize;
            for file in res.files.into_iter() {
                if seen.insert(file.id) {
                    all_files.push(file);
                    added += 1;
                }
            }

            if added == 0 {
                break;
            }

            if let Some(total) = total_count
                && all_files.len() as u64 >= total
            {
                break;
            }

            page += 1;
        }

        Ok(AlbumFilesPage {
            success: true,
            files: all_files,
            count: total_count.unwrap_or(0),
            albums,
            base_domain,
        })
    }

    /// List files in an album ("folder") for a specific page.
    ///
    /// Page numbers are zero-based (`page = 0` is the first page). This is intentionally exposed
    /// so a higher-level pagination helper can be added later.
    ///
    /// Requires an auth token (see [`CyberdropClient::with_auth_token`]).
    ///
    /// # Errors
    ///
    /// - [`CyberdropError::MissingAuthToken`] if the client has no configured token
    /// - [`CyberdropError::AuthenticationFailed`] / [`CyberdropError::RequestFailed`] for non-2xx statuses
    /// - [`CyberdropError::Api`] for service-reported failures
    /// - [`CyberdropError::MissingField`] if expected fields are missing in the response body
    /// - [`CyberdropError::Http`] for transport failures (including timeouts)
    pub async fn list_album_files_page(
        &self,
        album_id: u64,
        page: u64,
    ) -> Result<AlbumFilesPage, CyberdropError> {
        let path = format!("api/album/{album_id}/{page}");
        let response: AlbumFilesResponse = self.transport.get_json(&path, true).await?;
        AlbumFilesPage::try_from(response)
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

        let response: CreateAlbumResponse = self
            .transport
            .post_json("api/albums", &payload, true)
            .await?;

        u64::try_from(response)
    }

    /// Edit an existing album ("folder").
    ///
    /// This endpoint updates album metadata such as name/description and visibility flags.
    /// It can also request a new link identifier.
    ///
    /// Requires an auth token.
    ///
    /// # Returns
    ///
    /// The API returns either a `name` (typical edits) or an `identifier` (when requesting a new
    /// link). This crate exposes both as optional fields on [`EditAlbumResult`].
    ///
    /// # Errors
    ///
    /// - [`CyberdropError::MissingAuthToken`] if the client has no configured token
    /// - [`CyberdropError::AuthenticationFailed`] / [`CyberdropError::RequestFailed`] for non-2xx statuses
    /// - [`CyberdropError::Api`] for service-reported failures
    /// - [`CyberdropError::MissingField`] if the response is missing expected fields
    /// - [`CyberdropError::Http`] for transport failures (including timeouts)
    pub async fn edit_album(
        &self,
        id: u64,
        name: impl Into<String>,
        description: impl Into<String>,
        download: bool,
        public: bool,
        request_new_link: bool,
    ) -> Result<EditAlbumResult, CyberdropError> {
        let payload = EditAlbumRequest {
            id,
            name: name.into(),
            description: description.into(),
            download,
            public,
            request_link: request_new_link,
        };

        let response: EditAlbumResponse = self
            .transport
            .post_json("api/albums/edit", &payload, true)
            .await?;

        EditAlbumResult::try_from(response)
    }

    /// Request a new public link identifier for an existing album, preserving its current settings.
    ///
    /// This is a convenience wrapper around:
    /// 1) [`CyberdropClient::list_albums`] (to fetch current album settings)
    /// 2) [`CyberdropClient::edit_album`] with `request_new_link = true`
    ///
    /// Requires an auth token (see [`CyberdropClient::with_auth_token`]).
    ///
    /// # Returns
    ///
    /// The new album public URL in the form `https://cyberdrop.cr/a/<identifier>`.
    ///
    /// Note: this URL is always built against `https://cyberdrop.cr/` (it does not use the
    /// client's configured base URL).
    ///
    /// # Errors
    ///
    /// - [`CyberdropError::MissingAuthToken`] if the client has no configured token
    /// - [`CyberdropError::AlbumNotFound`] if `album_id` is not present in the album list
    /// - [`CyberdropError::AuthenticationFailed`] / [`CyberdropError::RequestFailed`] for non-2xx statuses
    /// - [`CyberdropError::Api`] for service-reported failures
    /// - [`CyberdropError::MissingField`] if the API omits the new identifier
    /// - [`CyberdropError::Http`] for transport failures (including timeouts)
    pub async fn request_new_album_link(&self, album_id: u64) -> Result<String, CyberdropError> {
        let album = self.get_album_by_id(album_id).await?;

        let edited = self
            .edit_album(
                album_id,
                album.name,
                album.description,
                album.download,
                album.public,
                true,
            )
            .await?;

        let identifier = edited.identifier.ok_or(CyberdropError::MissingField(
            "edit album response missing identifier",
        ))?;

        let identifier = identifier.trim_start_matches('/');
        Ok(identifier.to_string())
    }

    /// Update an album name, preserving existing description and visibility flags.
    ///
    /// This is a convenience wrapper around:
    /// 1) [`CyberdropClient::list_albums`] (to fetch current album settings)
    /// 2) [`CyberdropClient::edit_album`] with `request_new_link = false`
    ///
    /// Requires an auth token (see [`CyberdropClient::with_auth_token`]).
    ///
    /// # Returns
    ///
    /// The API response mapped into an [`EditAlbumResult`].
    ///
    /// # Errors
    ///
    /// - [`CyberdropError::MissingAuthToken`] if the client has no configured token
    /// - [`CyberdropError::AlbumNotFound`] if `album_id` is not present in the album list
    /// - [`CyberdropError::AuthenticationFailed`] / [`CyberdropError::RequestFailed`] for non-2xx statuses
    /// - [`CyberdropError::Api`] for service-reported failures
    /// - [`CyberdropError::MissingField`] if the response is missing expected fields
    /// - [`CyberdropError::Http`] for transport failures (including timeouts)
    pub async fn set_album_name(
        &self,
        album_id: u64,
        name: impl Into<String>,
    ) -> Result<EditAlbumResult, CyberdropError> {
        let album = self.get_album_by_id(album_id).await?;
        self.edit_album(
            album_id,
            name,
            album.description,
            album.download,
            album.public,
            false,
        )
        .await
    }

    /// Update an album description, preserving existing name and visibility flags.
    ///
    /// This is a convenience wrapper around:
    /// 1) [`CyberdropClient::list_albums`] (to fetch current album settings)
    /// 2) [`CyberdropClient::edit_album`] with `request_new_link = false`
    ///
    /// Requires an auth token (see [`CyberdropClient::with_auth_token`]).
    ///
    /// # Returns
    ///
    /// The API response mapped into an [`EditAlbumResult`].
    ///
    /// # Errors
    ///
    /// - [`CyberdropError::MissingAuthToken`] if the client has no configured token
    /// - [`CyberdropError::AlbumNotFound`] if `album_id` is not present in the album list
    /// - [`CyberdropError::AuthenticationFailed`] / [`CyberdropError::RequestFailed`] for non-2xx statuses
    /// - [`CyberdropError::Api`] for service-reported failures
    /// - [`CyberdropError::MissingField`] if the response is missing expected fields
    /// - [`CyberdropError::Http`] for transport failures (including timeouts)
    pub async fn set_album_description(
        &self,
        album_id: u64,
        description: impl Into<String>,
    ) -> Result<EditAlbumResult, CyberdropError> {
        let album = self.get_album_by_id(album_id).await?;
        self.edit_album(
            album_id,
            album.name,
            description,
            album.download,
            album.public,
            false,
        )
        .await
    }

    /// Update an album download flag, preserving existing name/description and public flag.
    ///
    /// This is a convenience wrapper around:
    /// 1) [`CyberdropClient::list_albums`] (to fetch current album settings)
    /// 2) [`CyberdropClient::edit_album`] with `request_new_link = false`
    ///
    /// Requires an auth token (see [`CyberdropClient::with_auth_token`]).
    ///
    /// # Returns
    ///
    /// The API response mapped into an [`EditAlbumResult`].
    ///
    /// # Errors
    ///
    /// - [`CyberdropError::MissingAuthToken`] if the client has no configured token
    /// - [`CyberdropError::AlbumNotFound`] if `album_id` is not present in the album list
    /// - [`CyberdropError::AuthenticationFailed`] / [`CyberdropError::RequestFailed`] for non-2xx statuses
    /// - [`CyberdropError::Api`] for service-reported failures
    /// - [`CyberdropError::MissingField`] if the response is missing expected fields
    /// - [`CyberdropError::Http`] for transport failures (including timeouts)
    pub async fn set_album_download(
        &self,
        album_id: u64,
        download: bool,
    ) -> Result<EditAlbumResult, CyberdropError> {
        let album = self.get_album_by_id(album_id).await?;
        self.edit_album(
            album_id,
            album.name,
            album.description,
            download,
            album.public,
            false,
        )
        .await
    }

    /// Update an album public flag, preserving existing name/description and download flag.
    ///
    /// This is a convenience wrapper around:
    /// 1) [`CyberdropClient::list_albums`] (to fetch current album settings)
    /// 2) [`CyberdropClient::edit_album`] with `request_new_link = false`
    ///
    /// Requires an auth token (see [`CyberdropClient::with_auth_token`]).
    ///
    /// # Returns
    ///
    /// The API response mapped into an [`EditAlbumResult`].
    ///
    /// # Errors
    ///
    /// - [`CyberdropError::MissingAuthToken`] if the client has no configured token
    /// - [`CyberdropError::AlbumNotFound`] if `album_id` is not present in the album list
    /// - [`CyberdropError::AuthenticationFailed`] / [`CyberdropError::RequestFailed`] for non-2xx statuses
    /// - [`CyberdropError::Api`] for service-reported failures
    /// - [`CyberdropError::MissingField`] if the response is missing expected fields
    /// - [`CyberdropError::Http`] for transport failures (including timeouts)
    pub async fn set_album_public(
        &self,
        album_id: u64,
        public: bool,
    ) -> Result<EditAlbumResult, CyberdropError> {
        let album = self.get_album_by_id(album_id).await?;
        self.edit_album(
            album_id,
            album.name,
            album.description,
            album.download,
            public,
            false,
        )
        .await
    }

    /// Upload a single file.
    ///
    /// Requires an auth token.
    ///
    /// Implementation notes:
    /// - Small files are streamed.
    /// - Large files are uploaded in chunks from disk.
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
        self.upload_file_with_progress(file_path, album_id, |_| {})
            .await
    }

    /// Upload a single file and emit per-file progress updates.
    ///
    /// The `on_progress` callback is invoked as bytes are streamed or as chunks complete.
    pub async fn upload_file_with_progress<F>(
        &self,
        file_path: impl AsRef<Path>,
        album_id: Option<u64>,
        on_progress: F,
    ) -> Result<UploadedFile, CyberdropError>
    where
        F: FnMut(UploadProgress) + Send + 'static,
    {
        let prepared = prepare_upload_file(file_path.as_ref()).await?;
        let upload_url = self.get_upload_url().await?;

        match select_upload_strategy(prepared.total_size) {
            UploadStrategy::Single => {
                self.upload_small_file_with_progress(upload_url, prepared, album_id, on_progress)
                    .await
            }
            UploadStrategy::Chunked => {
                self.upload_chunked_file_with_progress(upload_url, prepared, album_id, on_progress)
                    .await
            }
        }
    }

    async fn upload_small_file_with_progress<F>(
        &self,
        upload_url: Url,
        prepared: PreparedUpload,
        album_id: Option<u64>,
        on_progress: F,
    ) -> Result<UploadedFile, CyberdropError>
    where
        F: FnMut(UploadProgress) + Send + 'static,
    {
        let PreparedUpload {
            file,
            file_name,
            mime,
            total_size,
        } = prepared;

        let stream = ReaderStream::new(file);
        let progress_stream =
            ProgressStream::new(stream, total_size, file_name.clone(), on_progress);
        let body = Body::wrap_stream(progress_stream);
        let part = reqwest::multipart::Part::stream_with_length(body, total_size)
            .file_name(file_name.clone());
        let part = match part.mime_str(&mime) {
            Ok(p) => p,
            Err(_) => reqwest::multipart::Part::bytes(Vec::new()).file_name(file_name.clone()),
        };
        let form = Form::new().part("files[]", part);
        let response: UploadResponse = self
            .transport
            .post_single_upload_url(upload_url, form, album_id)
            .await?;

        UploadedFile::try_from(response)
    }

    async fn upload_chunked_file_with_progress<F>(
        &self,
        upload_url: Url,
        prepared: PreparedUpload,
        album_id: Option<u64>,
        mut on_progress: F,
    ) -> Result<UploadedFile, CyberdropError>
    where
        F: FnMut(UploadProgress) + Send + 'static,
    {
        let PreparedUpload {
            mut file,
            file_name,
            mime,
            total_size,
        } = prepared;

        let plan = ChunkUploadPlan::new(total_size);
        let uuid = Uuid::new_v4().to_string();
        let mut bytes_sent = 0u64;
        let mut chunk_index = 0u64;
        let mut buffer = Vec::with_capacity(plan.chunk_size as usize);

        loop {
            buffer.clear();
            let read = file.read_buf(&mut buffer).await?;
            if read == 0 {
                break;
            }

            let response: serde_json::Value = self
                .transport
                .post_chunk_url(
                    upload_url.clone(),
                    buffer,
                    build_chunk_fields(
                        &uuid,
                        chunk_index,
                        plan,
                        total_size,
                        &file_name,
                        &mime,
                        album_id,
                    ),
                )
                .await?;

            if !response
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                return Err(CyberdropError::Api(format!("chunk {} failed", chunk_index)));
            }

            bytes_sent = bytes_sent.saturating_add(read as u64);
            on_progress(UploadProgress {
                file_name: file_name.clone(),
                bytes_sent,
                total_bytes: total_size,
            });
            chunk_index = chunk_index.saturating_add(1);
            buffer = Vec::with_capacity(plan.chunk_size as usize);
        }

        self.finish_chunked_upload(upload_url, uuid, file_name, mime, album_id)
            .await
    }

    async fn finish_chunked_upload(
        &self,
        upload_url: Url,
        uuid: String,
        file_name: String,
        mime: String,
        album_id: Option<u64>,
    ) -> Result<UploadedFile, CyberdropError> {
        let payload = build_finish_chunks_payload(uuid, file_name, mime, album_id);
        let finish_url = finish_chunks_url(upload_url);

        let response: UploadResponse = self
            .transport
            .post_json_with_upload_headers_url(finish_url, &payload)
            .await?;

        UploadedFile::try_from(response)
    }
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

impl Default for CyberdropClientBuilder {
    fn default() -> Self {
        Self::new()
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
    fn select_upload_strategy_uses_chunk_threshold() {
        assert_eq!(select_upload_strategy(0), UploadStrategy::Single);
        assert_eq!(select_upload_strategy(CHUNK_SIZE), UploadStrategy::Single);
        assert_eq!(
            select_upload_strategy(CHUNK_SIZE + 1),
            UploadStrategy::Chunked
        );
    }

    #[test]
    fn chunk_upload_plan_calculates_chunk_boundaries() {
        let one_chunk = ChunkUploadPlan::new(CHUNK_SIZE);
        assert_eq!(one_chunk.chunk_size, CHUNK_SIZE);
        assert_eq!(one_chunk.total_chunks, 1);
        assert_eq!(one_chunk.byte_offset(0), 0);

        let partial_second_chunk = ChunkUploadPlan::new(CHUNK_SIZE + 1);
        assert_eq!(partial_second_chunk.chunk_size, CHUNK_SIZE);
        assert_eq!(partial_second_chunk.total_chunks, 2);
        assert_eq!(partial_second_chunk.byte_offset(1), CHUNK_SIZE);

        let empty_file_plan = ChunkUploadPlan::new(0);
        assert_eq!(empty_file_plan.chunk_size, 1);
        assert_eq!(empty_file_plan.total_chunks, 1);
    }

    #[test]
    fn build_chunk_fields_maps_plan_and_metadata() {
        let plan = ChunkUploadPlan::new(CHUNK_SIZE + 1);
        let fields = build_chunk_fields(
            "upload-id",
            1,
            plan,
            CHUNK_SIZE + 1,
            "image.jpg",
            "image/jpeg",
            Some(42),
        );

        assert_eq!(fields.uuid, "upload-id");
        assert_eq!(fields.chunk_index, 1);
        assert_eq!(fields.total_size, CHUNK_SIZE + 1);
        assert_eq!(fields.chunk_size, CHUNK_SIZE);
        assert_eq!(fields.total_chunks, 2);
        assert_eq!(fields.byte_offset, CHUNK_SIZE);
        assert_eq!(fields.file_name, "image.jpg");
        assert_eq!(fields.mime_type, "image/jpeg");
        assert_eq!(fields.album_id, Some(42));
    }

    #[test]
    fn build_finish_chunks_payload_preserves_file_metadata() {
        let payload = build_finish_chunks_payload(
            "upload-id".to_string(),
            "image.jpg".to_string(),
            "image/jpeg".to_string(),
            Some(42),
        );

        assert_eq!(payload.files.len(), 1);
        let file = &payload.files[0];
        assert_eq!(file.uuid, "upload-id");
        assert_eq!(file.original, "image.jpg");
        assert_eq!(file.r#type, "image/jpeg");
        assert_eq!(file.albumid, Some(42));
        assert_eq!(file.filelength, None);
        assert_eq!(file.age, None);
    }

    #[test]
    fn finish_chunks_url_replaces_upload_path() {
        let url = Url::parse("https://node.example/upload?token=abc").unwrap();
        let finish_url = finish_chunks_url(url);

        assert_eq!(
            finish_url.as_str(),
            "https://node.example/api/upload/finishchunks?token=abc"
        );
    }

    #[tokio::test]
    async fn prepare_upload_file_rejects_missing_file_name_before_opening() {
        match prepare_upload_file(Path::new("")).await {
            Err(CyberdropError::InvalidFileName) => {}
            Err(err) => panic!("expected invalid file name, got {err}"),
            Ok(_) => panic!("expected invalid file name, got prepared upload"),
        }
    }
}
