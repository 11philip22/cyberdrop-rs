use std::{path::Path, time::Duration};

mod error;
mod models;

pub use error::CyberdropError;
pub use models::{Album, AlbumsList, AuthToken, Permissions, TokenVerification, UploadedFile};
use reqwest::{Client, ClientBuilder, RequestBuilder, Url, multipart::Form};

use models::{
    AlbumsResponse, CreateAlbumRequest, CreateAlbumResponse, LoginRequest, LoginResponse,
    UploadResponse, VerifyTokenRequest, VerifyTokenResponse,
};

const DEFAULT_BASE_URL: &str = "https://cyberdrop.cr/";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Thin async HTTP client for Cyberdrop endpoints.
#[derive(Debug, Clone)]
pub struct CyberdropClient {
    client: Client,
    base_url: Url,
    auth_token: Option<String>,
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
        self.auth_token.as_deref()
    }

    /// Return a clone of this client that applies bearer auth to requests.
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Execute a GET request against a relative path on the Cyberdrop API.
    pub async fn get(&self, path: impl AsRef<str>) -> Result<reqwest::Response, CyberdropError> {
        let url = self.join_path(path.as_ref())?;
        self.apply_auth(self.client.get(url))
            .send()
            .await
            .map_err(CyberdropError::from)
    }

    /// Authenticate to retrieve a bearer token.
    pub async fn login(
        &self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<AuthToken, CyberdropError> {
        let url = self.join_path("api/login")?;
        let payload = LoginRequest {
            username: username.into(),
            password: password.into(),
        };

        let response = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(CyberdropError::from)?;

        if !response.status().is_success() {
            return Err(CyberdropError::AuthenticationFailed(response.status()));
        }

        let body: LoginResponse = response.json().await?;
        let token = body
            .token
            .ok_or(CyberdropError::MissingToken)?
            .into_string();

        Ok(AuthToken { token })
    }

    /// Verify a bearer token and fetch associated permissions.
    pub async fn verify_token(
        &self,
        token: impl Into<String>,
    ) -> Result<TokenVerification, CyberdropError> {
        let url = self.join_path("api/tokens/verify")?;
        let payload = VerifyTokenRequest {
            token: token.into(),
        };

        let response = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(CyberdropError::from)?;

        if !response.status().is_success() {
            return Err(CyberdropError::AuthenticationFailed(response.status()));
        }

        let body: VerifyTokenResponse = response.json().await?;
        parse_verification_response(body)
    }

    /// List albums for the authenticated user.
    pub async fn list_albums(&self) -> Result<AlbumsList, CyberdropError> {
        if self.auth_token.is_none() {
            return Err(CyberdropError::MissingAuthToken);
        }

        let url = self.join_path("api/albums")?;
        let response = self
            .apply_auth(self.client.get(url))
            .send()
            .await
            .map_err(CyberdropError::from)?;

        if !response.status().is_success() {
            return Err(CyberdropError::AuthenticationFailed(response.status()));
        }

        let body: AlbumsResponse = response.json().await?;
        parse_albums_response(body)
    }

    /// Create a new album.
    pub async fn create_album(
        &self,
        name: impl Into<String>,
        description: Option<impl Into<String>>,
    ) -> Result<u64, CyberdropError> {
        if self.auth_token.is_none() {
            return Err(CyberdropError::MissingAuthToken);
        }

        let url = self.join_path("api/albums")?;
        let payload = CreateAlbumRequest {
            name: name.into(),
            description: description.map(Into::into),
        };

        let response = self
            .apply_auth(self.client.post(url))
            .json(&payload)
            .send()
            .await
            .map_err(CyberdropError::from)?;

        if !response.status().is_success() {
            return Err(CyberdropError::AuthenticationFailed(response.status()));
        }

        let body: CreateAlbumResponse = response.json().await?;
        parse_create_album_response(body)
    }

    /// Upload a single file (up to service limits).
    pub async fn upload_file(
        &self,
        file_path: impl AsRef<Path>,
        album_id: Option<u64>,
    ) -> Result<UploadedFile, CyberdropError> {
        if self.auth_token.is_none() {
            return Err(CyberdropError::MissingAuthToken);
        }

        let file_path = file_path.as_ref();
        let file_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(CyberdropError::InvalidFileName)?;
        let bytes = std::fs::read(file_path)?;

        let part = reqwest::multipart::Part::bytes(bytes).file_name(file_name.to_string());
        let form = Form::new().part("files[]", part);

        let url = self.join_path("api/upload")?;
        let response = self
            .apply_auth(self.client.post(url))
            .header("albumid", album_id.unwrap_or_default())
            .multipart(form)
            .send()
            .await
            .map_err(CyberdropError::from)?;

        if !response.status().is_success() {
            return Err(CyberdropError::AuthenticationFailed(response.status()));
        }

        let body: UploadResponse = response.json().await?;
        parse_upload_response(body)
    }

    fn join_path(&self, path: &str) -> Result<Url, CyberdropError> {
        Ok(self.base_url.join(path)?)
    }

    fn apply_auth(&self, builder: RequestBuilder) -> RequestBuilder {
        if let Some(token) = &self.auth_token {
            builder
                .bearer_auth(token)
                .header("Token", token)
                .header("token", token)
        } else {
            builder
        }
    }
}

/// Builder for [`CyberdropClient`].
#[derive(Debug)]
pub struct CyberdropClientBuilder {
    base_url: Option<Url>,
    user_agent: Option<String>,
    timeout: Duration,
    auth_token: Option<String>,
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
        self.auth_token = Some(token.into());
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

fn parse_verification_response(
    body: VerifyTokenResponse,
) -> Result<TokenVerification, CyberdropError> {
    let success = body.success.ok_or(CyberdropError::MissingField(
        "verification response missing success",
    ))?;
    let username = body.username.ok_or(CyberdropError::MissingField(
        "verification response missing username",
    ))?;
    let permissions = body.permissions.ok_or(CyberdropError::MissingField(
        "verification response missing permissions",
    ))?;

    Ok(TokenVerification {
        success,
        username,
        permissions,
    })
}

fn parse_albums_response(body: AlbumsResponse) -> Result<AlbumsList, CyberdropError> {
    let success = body.success.ok_or(CyberdropError::MissingField(
        "albums response missing success",
    ))?;

    let albums = body.albums.ok_or(CyberdropError::MissingField(
        "albums response missing albums",
    ))?;

    let home_domain = match body.home_domain {
        Some(url) => Some(Url::parse(&url)?),
        None => None,
    };

    Ok(AlbumsList {
        success,
        albums,
        home_domain,
    })
}

fn parse_create_album_response(body: CreateAlbumResponse) -> Result<u64, CyberdropError> {
    if body.success.unwrap_or(false) {
        return body.id.ok_or(CyberdropError::MissingField(
            "create album response missing id",
        ));
    }

    let msg = body
        .description
        .or(body.message)
        .unwrap_or_else(|| "create album failed".to_string());

    if msg.to_lowercase().contains("already an album") {
        Err(CyberdropError::AlbumAlreadyExists(msg))
    } else {
        Err(CyberdropError::Api(msg))
    }
}

fn parse_upload_response(body: UploadResponse) -> Result<UploadedFile, CyberdropError> {
    if body.success.unwrap_or(false) {
        let first =
            body.files
                .and_then(|mut files| files.pop())
                .ok_or(CyberdropError::MissingField(
                    "upload response missing files",
                ))?;
        let url = Url::parse(&first.url)?;
        Ok(UploadedFile {
            name: first.name,
            url: url.to_string(),
        })
    } else {
        let msg = body
            .description
            .unwrap_or_else(|| "upload failed".to_string());
        Err(CyberdropError::Api(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CreateAlbumResponse;

    #[test]
    fn builds_with_defaults() {
        let client = CyberdropClient::builder().build().unwrap();
        assert_eq!(client.base_url().as_str(), DEFAULT_BASE_URL);
    }

    #[test]
    fn accepts_custom_base_url() {
        let url = "https://example.test/";
        let client = CyberdropClient::new(url).unwrap();
        assert_eq!(client.base_url().as_str(), url);
    }

    #[test]
    fn join_path_keeps_ordering() {
        let client = CyberdropClient::builder()
            .base_url("https://example.test/root/")
            .unwrap()
            .build()
            .unwrap();

        let url = client.join_path("api/v1").unwrap();
        assert_eq!(url.as_str(), "https://example.test/root/api/v1");
    }

    #[test]
    fn builder_sets_auth_token() {
        let client = CyberdropClient::builder()
            .auth_token("abc123")
            .build()
            .unwrap();
        assert_eq!(client.auth_token(), Some("abc123"));
    }

    #[test]
    fn with_auth_token_applies_value() {
        let client = CyberdropClient::builder().build().unwrap();
        let authed = client.with_auth_token("token-value");
        assert_eq!(authed.auth_token(), Some("token-value"));
    }

    #[test]
    fn parses_verification_response() {
        let response = VerifyTokenResponse {
            success: Some(true),
            username: Some("yesboi".into()),
            permissions: Some(Permissions {
                user: true,
                poweruser: false,
                moderator: false,
                admin: false,
                superadmin: false,
            }),
        };

        let verification = parse_verification_response(response).unwrap();
        assert!(verification.success);
        assert_eq!(verification.username, "yesboi");
        assert!(verification.permissions.user);
        assert!(!verification.permissions.admin);
    }

    #[test]
    fn parses_albums_response() {
        let response = AlbumsResponse {
            success: Some(true),
            albums: Some(vec![Album {
                id: 143794,
                name: "ml".into(),
                timestamp: 1_768_610_324,
                identifier: "quLyYpj0".into(),
                edited_at: 1_768_612_201,
                download: true,
                public: true,
                description: "".into(),
                files: 185,
            }]),
            home_domain: Some("https://cyberdrop.cr/".into()),
        };

        let result = parse_albums_response(response).unwrap();
        assert!(result.success);
        assert_eq!(result.albums.len(), 1);
        assert_eq!(result.albums[0].identifier, "quLyYpj0");
        assert_eq!(
            result.home_domain.unwrap().as_str(),
            "https://cyberdrop.cr/"
        );
    }

    #[test]
    fn parse_create_album_success() {
        let response = CreateAlbumResponse {
            success: Some(true),
            id: Some(123),
            message: None,
            description: None,
        };
        let id = parse_create_album_response(response).unwrap();
        assert_eq!(id, 123);
    }

    #[test]
    fn parse_create_album_duplicate_maps_error() {
        let response = CreateAlbumResponse {
            success: Some(false),
            id: None,
            message: None,
            description: Some("There is already an album with that name.".into()),
        };
        match parse_create_album_response(response) {
            Err(CyberdropError::AlbumAlreadyExists(msg)) => {
                assert!(msg.contains("already an album"));
            }
            other => panic!("expected AlbumAlreadyExists, got {other:?}"),
        }
    }

    #[test]
    fn parse_create_album_other_error_maps_api() {
        let response = CreateAlbumResponse {
            success: Some(false),
            id: None,
            message: None,
            description: Some("No album name specified.".into()),
        };
        match parse_create_album_response(response) {
            Err(CyberdropError::Api(msg)) => {
                assert!(msg.contains("No album name specified"));
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[test]
    fn parse_upload_response_success() {
        let response = UploadResponse {
            success: Some(true),
            description: None,
            files: Some(vec![UploadedFile {
                name: "file.mp4".into(),
                url: "https://cyberdrop.cr/f/abc123?video".into(),
            }]),
        };

        let file = parse_upload_response(response).unwrap();
        assert_eq!(file.name, "file.mp4");
        assert!(file.url.contains("/f/abc123"));
    }

    #[test]
    fn parse_upload_response_failure_maps_api() {
        let response = UploadResponse {
            success: Some(false),
            description: Some("upload failed".into()),
            files: None,
        };

        match parse_upload_response(response) {
            Err(CyberdropError::Api(msg)) => assert!(msg.contains("upload failed")),
            other => panic!("expected Api error, got {other:?}"),
        }
    }
}
