use std::{path::Path, time::Duration};

use reqwest::{
    multipart::Form, Client, ClientBuilder, Method, RequestBuilder, StatusCode, Url,
};
use serde::de::DeserializeOwned;

mod error;
mod models;

pub use error::CyberdropError;
pub use models::{Album, AlbumsList, AuthToken, Permissions, TokenVerification, UploadedFile};
use models::{
    AlbumsResponse, CreateAlbumRequest, CreateAlbumResponse, LoginRequest, LoginResponse,
    UploadResponse, VerifyTokenRequest, VerifyTokenResponse,
};

const DEFAULT_BASE_URL: &str = "https://cyberdrop.cr/";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Async HTTP client for Cyberdrop endpoints.
#[derive(Debug, Clone)]
pub struct CyberdropClient {
    client: Client,
    base_url: Url,
    auth_token: Option<AuthToken>,
}

impl CyberdropClient {
    /// Build a client with a custom base URL.
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, CyberdropError> {
        CyberdropClientBuilder::new().base_url(base_url)?.build()
    }

    /// Start configuring a client with sensible defaults.
    pub fn builder() -> CyberdropClientBuilder {
        CyberdropClientBuilder::new()
    }

    /// Current base URL.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Current auth token if configured.
    pub fn auth_token(&self) -> Option<&str> {
        self.auth_token.as_ref().map(AuthToken::as_str)
    }

    /// Return a clone of this client that applies bearer auth to requests.
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(AuthToken::new(token));
        self
    }

    /// Execute a GET request against a relative path on the Cyberdrop API.
    pub async fn get(&self, path: impl AsRef<str>) -> Result<reqwest::Response, CyberdropError> {
        let builder = self
            .client
            .get(self.join_path(path.as_ref())?);
        let builder = self.apply_auth_if_present(builder);
        builder.send().await.map_err(CyberdropError::from)
    }

    /// Authenticate to retrieve a bearer token.
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
            .post_json("api/login", &payload, false)
            .await?;

        AuthToken::try_from(response)
    }

    /// Verify a bearer token and fetch associated permissions.
    pub async fn verify_token(
        &self,
        token: impl Into<String>,
    ) -> Result<TokenVerification, CyberdropError> {
        let payload = VerifyTokenRequest {
            token: token.into(),
        };

        let response: VerifyTokenResponse = self
            .post_json("api/tokens/verify", &payload, false)
            .await?;

        TokenVerification::try_from(response)
    }

    /// List albums for the authenticated user.
    pub async fn list_albums(&self) -> Result<AlbumsList, CyberdropError> {
        let response: AlbumsResponse = self.get_json("api/albums", true).await?;
        AlbumsList::try_from(response)
    }

    /// Create a new album.
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
            .post_json("api/albums", &payload, true)
            .await?;

        u64::try_from(response)
    }

    /// Upload a single file (up to service limits).
    pub async fn upload_file(
        &self,
        file_path: impl AsRef<Path>,
        album_id: Option<u64>,
    ) -> Result<UploadedFile, CyberdropError> {
        let file_path = file_path.as_ref();
        let file_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(CyberdropError::InvalidFileName)?;
        let bytes = std::fs::read(file_path)?;

        let part = reqwest::multipart::Part::bytes(bytes).file_name(file_name.to_string());
        let form = Form::new().part("files[]", part);

        let response: UploadResponse = self
            .post_multipart("api/upload", form, album_id)
            .await?;

        UploadedFile::try_from(response)
    }

    async fn get_json<T>(&self, path: &str, requires_auth: bool) -> Result<T, CyberdropError>
    where
        T: DeserializeOwned,
    {
        let builder = self.build_request(Method::GET, path, requires_auth)?;
        self.send_json(builder).await
    }

    async fn post_json<B, T>(
        &self,
        path: &str,
        body: &B,
        requires_auth: bool,
    ) -> Result<T, CyberdropError>
    where
        B: serde::Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let builder = self
            .build_request(Method::POST, path, requires_auth)?
            .json(body);
        self.send_json(builder).await
    }

    async fn post_multipart<T>(
        &self,
        path: &str,
        form: Form,
        album_id: Option<u64>,
    ) -> Result<T, CyberdropError>
    where
        T: DeserializeOwned,
    {
        let mut builder = self.build_request(Method::POST, path, true)?;
        if let Some(id) = album_id {
            builder = builder.header("albumid", id);
        }
        let builder = builder.multipart(form);
        self.send_json(builder).await
    }

    async fn send_json<T>(&self, builder: RequestBuilder) -> Result<T, CyberdropError>
    where
        T: DeserializeOwned,
    {
        let response = builder.send().await?;
        Self::map_status(response.status())?;
        Ok(response.json().await?)
    }

    fn build_request(
        &self,
        method: Method,
        path: &str,
        requires_auth: bool,
    ) -> Result<RequestBuilder, CyberdropError> {
        let url = self.join_path(path)?;
        let builder = self.client.request(method, url);

        if requires_auth {
            self.apply_auth(builder)
        } else {
            Ok(builder)
        }
    }

    fn map_status(status: StatusCode) -> Result<(), CyberdropError> {
        if status.is_success() {
            return Ok(());
        }

        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            Err(CyberdropError::AuthenticationFailed(status))
        } else {
            Err(CyberdropError::RequestFailed(status))
        }
    }

    fn join_path(&self, path: &str) -> Result<Url, CyberdropError> {
        Ok(self.base_url.join(path)?)
    }

    fn apply_auth(&self, builder: RequestBuilder) -> Result<RequestBuilder, CyberdropError> {
        let token = self
            .auth_token
            .as_ref()
            .ok_or(CyberdropError::MissingAuthToken)?;

        Ok(Self::attach_token(builder, token))
    }

    fn apply_auth_if_present(&self, builder: RequestBuilder) -> RequestBuilder {
        match &self.auth_token {
            Some(token) => Self::attach_token(builder, token),
            None => builder,
        }
    }

    fn attach_token(builder: RequestBuilder, token: &AuthToken) -> RequestBuilder {
        builder
            .bearer_auth(token.as_str())
            .header("Token", token.as_str())
            .header("token", token.as_str())
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
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn build(self) -> Result<CyberdropClient, CyberdropError> {
        let base_url = match self.base_url {
            Some(url) => url,
            None => Url::parse(DEFAULT_BASE_URL)?,
        };

        let mut builder = self.builder.timeout(self.timeout);
        builder = builder.user_agent(self.user_agent.unwrap_or_else(default_user_agent));

        let client = builder.build()?;

        Ok(CyberdropClient {
            client,
            base_url,
            auth_token: self.auth_token,
        })
    }
}

fn default_user_agent() -> String {
    format!("cyberdrop-rs/{}", env!("CARGO_PKG_VERSION"))
}
