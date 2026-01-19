use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::CyberdropError;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct AuthToken {
    pub(crate) token: String,
}

impl AuthToken {
    pub fn new(token: impl Into<String>) -> Self {
        Self { token: token.into() }
    }

    pub fn as_str(&self) -> &str {
        &self.token
    }

    pub fn into_string(self) -> String {
        self.token
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Permissions {
    pub user: bool,
    pub poweruser: bool,
    pub moderator: bool,
    pub admin: bool,
    pub superadmin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenVerification {
    pub success: bool,
    pub username: String,
    pub permissions: Permissions,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Album {
    pub id: u64,
    pub name: String,
    pub timestamp: u64,
    pub identifier: String,
    pub edited_at: u64,
    pub download: bool,
    pub public: bool,
    pub description: String,
    pub files: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlbumsList {
    pub success: bool,
    pub albums: Vec<Album>,
    pub home_domain: Option<Url>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAlbumRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateAlbumResponse {
    pub success: Option<bool>,
    pub id: Option<u64>,
    pub message: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UploadResponse {
    pub success: Option<bool>,
    pub description: Option<String>,
    pub files: Option<Vec<UploadedFile>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct UploadedFile {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct LoginRequest {
    pub(crate) username: String,
    pub(crate) password: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LoginResponse {
    pub(crate) token: Option<AuthToken>,
}

#[derive(Debug, Serialize)]
pub(crate) struct VerifyTokenRequest {
    pub(crate) token: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VerifyTokenResponse {
    pub(crate) success: Option<bool>,
    pub(crate) username: Option<String>,
    pub(crate) permissions: Option<Permissions>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AlbumsResponse {
    pub(crate) success: Option<bool>,
    pub(crate) albums: Option<Vec<Album>>,
    pub(crate) home_domain: Option<String>,
}

impl TryFrom<LoginResponse> for AuthToken {
    type Error = CyberdropError;

    fn try_from(response: LoginResponse) -> Result<Self, Self::Error> {
        response.token.ok_or(CyberdropError::MissingToken)
    }
}

impl TryFrom<VerifyTokenResponse> for TokenVerification {
    type Error = CyberdropError;

    fn try_from(body: VerifyTokenResponse) -> Result<Self, Self::Error> {
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
}

impl TryFrom<AlbumsResponse> for AlbumsList {
    type Error = CyberdropError;

    fn try_from(body: AlbumsResponse) -> Result<Self, Self::Error> {
        if !body.success.unwrap_or(false) {
            return Err(CyberdropError::Api("failed to fetch albums".into()));
        }

        let albums = body
            .albums
            .ok_or(CyberdropError::MissingField("albums response missing albums"))?;

        let home_domain = match body.home_domain {
            Some(url) => Some(Url::parse(&url)?),
            None => None,
        };

        Ok(AlbumsList {
            success: true,
            albums,
            home_domain,
        })
    }
}

impl TryFrom<CreateAlbumResponse> for u64 {
    type Error = CyberdropError;

    fn try_from(body: CreateAlbumResponse) -> Result<Self, Self::Error> {
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
}

impl TryFrom<UploadResponse> for UploadedFile {
    type Error = CyberdropError;

    fn try_from(body: UploadResponse) -> Result<Self, Self::Error> {
        if body.success.unwrap_or(false) {
            let first = body
                .files
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
}
