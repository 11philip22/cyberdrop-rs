use std::time::Duration;

use reqwest::{Client, ClientBuilder, Url};

use crate::CyberdropError;
use crate::config::{DEFAULT_BASE_URL, DEFAULT_TIMEOUT};
use crate::token::AuthToken;
use crate::transport::Transport;

/// Async HTTP client for a subset of Cyberdrop endpoints.
///
/// Most higher-level methods map non-2xx responses to [`CyberdropError`]. For raw access where
/// you want to inspect status codes and bodies directly, use [`CyberdropClient::get`].
#[derive(Debug, Clone)]
pub struct CyberdropClient {
    pub(crate) transport: Transport,
}

/// Builder for [`CyberdropClient`].
#[derive(Debug)]
pub struct CyberdropClientBuilder {
    user_agent: Option<String>,
    timeout: Duration,
    auth_token: Option<AuthToken>,
    builder: ClientBuilder,
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
            builder: Client::builder(),
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
        let mut builder = self.builder.timeout(self.timeout);
        builder = builder.user_agent(self.user_agent.unwrap_or_else(default_user_agent));

        let client = builder.build()?;

        Ok(CyberdropClient {
            transport: Transport::new(client, Url::parse(DEFAULT_BASE_URL)?, self.auth_token),
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
