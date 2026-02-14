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

    async fn get_album_by_id(&self, album_id: u64) -> Result<crate::models::Album, CyberdropError> {
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
        let response: AlbumsResponse = self.transport.get_json("api/albums", true).await?;
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

            if let Some(total) = total_count {
                if all_files.len() as u64 >= total {
                    break;
                }
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
        Ok(format!("https://cyberdrop.cr/a/{identifier}"))
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
        mut on_progress: F,
    ) -> Result<UploadedFile, CyberdropError>
    where
        F: FnMut(UploadProgress) + Send + 'static,
    {
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

        let file = File::open(file_path).await?;
        let total_size = file.metadata().await?.len();
        let upload_url = self.get_upload_url().await?;

        // For small files, use the simple single-upload endpoint.
        if total_size <= CHUNK_SIZE {
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
            return UploadedFile::try_from(response);
        }

        let chunk_size = CHUNK_SIZE.min(total_size.max(1));
        let total_chunks = ((total_size + chunk_size - 1) / chunk_size).max(1);
        let uuid = Uuid::new_v4().to_string();
        let mut file = file;
        let mut bytes_sent = 0u64;
        let mut chunk_index = 0u64;

        loop {
            let mut buffer = vec![0u8; chunk_size as usize];
            let read = file.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            buffer.truncate(read);
            let byte_offset = chunk_index * chunk_size;

            let response: serde_json::Value = self
                .transport
                .post_chunk_url(
                    upload_url.clone(),
                    buffer,
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

        let finish_url = {
            let mut url = upload_url;
            url.set_path("/api/upload/finishchunks");
            url
        };

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

fn default_user_agent() -> String {
    // Match a browser UA; the service appears to expect browser-like clients.
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0".into()
}
