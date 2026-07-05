use std::time::Duration;

use reqwest::{
    Client, Method, RequestBuilder, StatusCode, Url,
    header::{ACCEPT, ACCEPT_LANGUAGE, HeaderName},
    multipart::Form,
};
use serde::de::DeserializeOwned;

use crate::CyberdropError;
use crate::config::{DEFAULT_BASE_URL, DEFAULT_TIMEOUT};
use crate::token::AuthToken;

/// Async HTTP client for a subset of Cyberdrop endpoints.
///
/// Most higher-level methods map non-2xx responses to [`CyberdropError`]. For raw access where
/// you want to inspect status codes and bodies directly, use [`CyberdropClient::get`].
#[derive(Debug, Clone)]
pub struct CyberdropClient {
    pub(crate) client: Client,
    pub(crate) base_url: Url,
    pub(crate) auth_token: Option<AuthToken>,
}

/// Builder for [`CyberdropClient`].
#[derive(Debug)]
pub struct CyberdropClientBuilder {
    user_agent: Option<String>,
    timeout: Duration,
    auth_token: Option<AuthToken>,
}

impl CyberdropClient {
    /// Build a client with the crate defaults.
    pub fn new() -> Result<Self, CyberdropError> {
        CyberdropClientBuilder::new().build()
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

    /// Current auth token if configured.
    pub fn auth_token(&self) -> Option<&str> {
        self.auth_token.as_ref().map(AuthToken::as_str)
    }

    /// Return a clone of this client that applies authentication to requests.
    ///
    /// The token is attached as an HTTP header named `token`.
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(AuthToken::new(token));
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
        let builder = self.apply_auth_if_present(self.client.get(self.join_path(path.as_ref())?));
        builder.send().await.map_err(CyberdropError::from)
    }

    pub(crate) async fn get_json<T>(
        &self,
        path: &str,
        requires_auth: bool,
    ) -> Result<T, CyberdropError>
    where
        T: DeserializeOwned,
    {
        let builder = self.build_request(Method::GET, path, requires_auth)?;
        self.send_json(builder).await
    }

    pub(crate) async fn get_json_with_header<T>(
        &self,
        path: &str,
        requires_auth: bool,
        header_name: &'static str,
        header_value: &'static str,
    ) -> Result<T, CyberdropError>
    where
        T: DeserializeOwned,
    {
        let builder = self
            .build_request(Method::GET, path, requires_auth)?
            .header(header_name, header_value);
        self.send_json(builder).await
    }

    pub(crate) async fn post_json<B, T>(
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

    pub(crate) async fn post_upload_json_url<B, T>(
        &self,
        url: Url,
        body: &B,
    ) -> Result<T, CyberdropError>
    where
        B: serde::Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let builder = self
            .upload_headers(self.build_request_url(Method::POST, url, true)?)
            .json(body);

        self.send_json(builder).await
    }

    pub(crate) async fn post_upload_multipart_url<T>(
        &self,
        url: Url,
        form: Form,
        album_id: Option<u64>,
    ) -> Result<T, CyberdropError>
    where
        T: DeserializeOwned,
    {
        let mut builder = self.upload_headers(self.build_request_url(Method::POST, url, true)?);
        if let Some(id) = album_id {
            builder = builder.header("albumid", id);
        }

        self.send_json(builder.multipart(form)).await
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
        self.build_request_url(method, url, requires_auth)
    }

    fn build_request_url(
        &self,
        method: Method,
        url: Url,
        requires_auth: bool,
    ) -> Result<RequestBuilder, CyberdropError> {
        let builder = self
            .client
            .request(method, url)
            .header(ACCEPT, "application/json, text/plain, */*")
            .header(ACCEPT_LANGUAGE, "nl,en-US;q=0.9,en;q=0.8");

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
        builder.header(HeaderName::from_static("token"), token.as_str())
    }

    fn upload_headers(&self, builder: RequestBuilder) -> RequestBuilder {
        let origin = self.base_url.origin().ascii_serialization();
        let referer = self.base_url.as_str();

        builder
            .header("X-Requested-With", "XMLHttpRequest")
            .header("striptags", "undefined")
            .header("Origin", origin)
            .header("Referer", referer)
            .header("Cache-Control", "no-cache")
            .header("Pragma", "no-cache")
    }
}

impl CyberdropClientBuilder {
    /// Create a new builder using the crate defaults.
    ///
    /// This is equivalent to [`CyberdropClient::builder`].
    pub fn new() -> Self {
        Self {
            user_agent: None,
            timeout: DEFAULT_TIMEOUT,
            auth_token: None,
        }
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
    /// Requests use `https://cyberdrop.cr/`.
    /// If no user agent is configured, a browser-like UA string is used.
    pub fn build(self) -> Result<CyberdropClient, CyberdropError> {
        let mut builder = Client::builder().timeout(self.timeout);
        builder = builder.user_agent(self.user_agent.unwrap_or_else(default_user_agent));

        let client = builder.build()?;

        Ok(CyberdropClient {
            client,
            base_url: Url::parse(DEFAULT_BASE_URL)?,
            auth_token: self.auth_token,
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
