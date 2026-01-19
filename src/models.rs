use reqwest::Url;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct AuthToken {
    pub(crate) token: String,
}

impl AuthToken {
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
