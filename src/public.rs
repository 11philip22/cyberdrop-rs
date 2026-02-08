//! Public-facing operations (non-API HTML flows).
//!
//! This module is intended for interacting with Cyberdrop public pages/links where the JSON API
//! is not used (for example, parsing public album pages and downloading media).
//!
//! The HTML parsing pieces are intentionally scaffolded but not implemented yet.

use std::time::Duration;

use reqwest::{Client, ClientBuilder, Url};

use crate::{CyberdropError, utils::default_user_agent};

const DEFAULT_BASE_URL: &str = "https://cyberdrop.cr/";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Client for public-facing (HTML) operations.
#[derive(Debug, Clone)]
pub struct CyberdropPublicClient {
    base_url: Url,
    client: Client,
}

/// Builder for [`CyberdropPublicClient`].
#[derive(Debug)]
pub struct CyberdropPublicClientBuilder {
    base_url: Option<Url>,
    user_agent: Option<String>,
    timeout: Duration,
    builder: ClientBuilder,
}

impl CyberdropPublicClient {
    /// Build a public client with a custom base URL.
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, CyberdropError> {
        CyberdropPublicClientBuilder::new()
            .base_url(base_url)?
            .build()
    }

    /// Start configuring a public client with the crate's defaults.
    pub fn builder() -> CyberdropPublicClientBuilder {
        CyberdropPublicClientBuilder::new()
    }

    /// Current base URL.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Borrow the underlying `reqwest` client (for advanced/custom requests).
    pub fn http_client(&self) -> &Client {
        &self.client
    }
}

impl CyberdropPublicClientBuilder {
    /// Create a new builder using the crate defaults.
    pub fn new() -> Self {
        Self {
            base_url: None,
            user_agent: None,
            timeout: DEFAULT_TIMEOUT,
            builder: Client::builder(),
        }
    }

    /// Override the base URL used for relative links.
    pub fn base_url(mut self, base_url: impl AsRef<str>) -> Result<Self, CyberdropError> {
        self.base_url = Some(Url::parse(base_url.as_ref())?);
        Ok(self)
    }

    /// Set a custom user agent header.
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Configure the request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Build a [`CyberdropPublicClient`].
    pub fn build(self) -> Result<CyberdropPublicClient, CyberdropError> {
        let base_url = match self.base_url {
            Some(url) => url,
            None => Url::parse(DEFAULT_BASE_URL)?,
        };

        let mut builder = self.builder.timeout(self.timeout);
        builder = builder.user_agent(self.user_agent.unwrap_or_else(default_user_agent));

        let client = builder.build()?;

        Ok(CyberdropPublicClient { base_url, client })
    }
}
