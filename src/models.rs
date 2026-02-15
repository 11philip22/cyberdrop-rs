use std::collections::HashMap;

use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde::de::{self, Visitor};
use std::fmt;

use crate::CyberdropError;

/// Authentication token returned by [`crate::CyberdropClient::login`] and
/// [`crate::CyberdropClient::register`].
///
/// This type is `#[serde(transparent)]` and typically deserializes from a JSON string.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct AuthToken {
    pub(crate) token: String,
}

impl AuthToken {
    /// Construct a new token wrapper.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }

    /// Borrow the underlying token string.
    pub fn as_str(&self) -> &str {
        &self.token
    }

    /// Consume this value and return the underlying token string.
    pub fn into_string(self) -> String {
        self.token
    }
}

/// Permission flags associated with a user/token verification response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Permissions {
    /// Whether the account has "user" privileges.
    pub user: bool,
    /// Whether the account has "poweruser" privileges.
    pub poweruser: bool,
    /// Whether the account has "moderator" privileges.
    pub moderator: bool,
    /// Whether the account has "admin" privileges.
    pub admin: bool,
    /// Whether the account has "superadmin" privileges.
    pub superadmin: bool,
}

/// Result of verifying a token via [`crate::CyberdropClient::verify_token`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenVerification {
    /// Whether the token verification succeeded.
    pub success: bool,
    /// Username associated with the token.
    pub username: String,
    /// Permission flags associated with the token.
    pub permissions: Permissions,
}

/// Album metadata as returned by the Cyberdrop API.
///
/// Field semantics (timestamps/flags) are intentionally documented minimally: values are exposed
/// as returned by the service without additional interpretation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Album {
    /// Album numeric ID.
    pub id: u64,
    /// Display name.
    pub name: String,
    /// Service-provided timestamp value.
    #[serde(default)]
    pub timestamp: u64,
    /// Service-provided identifier string.
    pub identifier: String,
    /// Service-provided "edited at" timestamp value.
    #[serde(default)]
    pub edited_at: u64,
    /// Service-provided download flag.
    #[serde(default)]
    pub download: bool,
    /// Service-provided public flag.
    #[serde(default)]
    pub public: bool,
    /// Album description (may be empty).
    #[serde(default)]
    pub description: String,
    /// Number of files in the album.
    #[serde(default)]
    pub files: u64,
}

/// Album listing for the authenticated user.
///
/// Values produced by this crate always have `success == true`; failures are returned as
/// [`CyberdropError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlbumsList {
    /// Whether the API request was successful.
    pub success: bool,
    /// Albums returned by the service.
    pub albums: Vec<Album>,
    /// Optional home domain returned by the service, parsed as a URL.
    pub home_domain: Option<Url>,
}

/// File metadata as returned by the album listing endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AlbumFile {
    pub id: u64,
    pub name: String,
    #[serde(rename = "userid", deserialize_with = "de_string_or_number")]
    pub user_id: String,
    #[serde(deserialize_with = "de_u64_or_string")]
    pub size: u64,
    pub timestamp: u64,
    #[serde(rename = "last_visited_at")]
    pub last_visited_at: Option<String>,
    pub slug: String,
    /// Base domain for file media (for example, `https://sun-i.cyberdrop.cr`).
    pub image: String,
    /// Nullable expiry date as returned by the service.
    pub expirydate: Option<String>,
    #[serde(rename = "albumid", deserialize_with = "de_string_or_number")]
    pub album_id: String,
    pub extname: String,
    /// Thumbnail path relative to `image` (for example, `thumbs/<...>.png`).
    pub thumb: String,
}

fn de_string_or_number<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct StringOrNumber;

    impl<'de> Visitor<'de> for StringOrNumber {
        type Value = String;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string or number")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(v.to_string())
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(v)
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(v.to_string())
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(v.to_string())
        }
    }

    deserializer.deserialize_any(StringOrNumber)
}

fn de_u64_or_string<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct U64OrString;

    impl<'de> Visitor<'de> for U64OrString {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a u64 or numeric string")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(v)
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if v < 0 {
                return Err(E::custom("negative value not allowed"));
            }
            Ok(v as u64)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            v.parse::<u64>().map_err(E::custom)
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            v.parse::<u64>().map_err(E::custom)
        }
    }

    deserializer.deserialize_any(U64OrString)
}

/// Page of files returned by the album listing endpoint.
///
/// This type represents a single response page; the API currently returns at most 25 files per
/// request and provides a total `count` for pagination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlbumFilesPage {
    /// Whether the API request was successful.
    pub success: bool,
    /// Files returned for the requested page.
    pub files: Vec<AlbumFile>,
    /// Total number of files in the album (across all pages).
    pub count: u64,
    /// Album mapping returned by the service (keyed by album id as a string).
    pub albums: HashMap<String, String>,
    /// Base domain returned by the service (parsed as a URL).
    ///
    /// Note: the API omits this field for empty albums, so it can be `None`.
    pub base_domain: Option<Url>,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EditAlbumRequest {
    pub(crate) id: u64,
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) download: bool,
    pub(crate) public: bool,
    #[serde(rename = "requestLink")]
    pub(crate) request_link: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EditAlbumResponse {
    pub(crate) success: Option<bool>,
    pub(crate) name: Option<String>,
    pub(crate) identifier: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) description: Option<String>,
}

/// Result of editing an album via [`crate::CyberdropClient::edit_album`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditAlbumResult {
    /// Updated name if the API returned it.
    pub name: Option<String>,
    /// New identifier if `request_new_link` was set and the API returned it.
    pub identifier: Option<String>,
}

/// Uploaded file metadata returned by [`crate::CyberdropClient::upload_file`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct UploadedFile {
    /// Name of the uploaded file.
    pub name: String,
    /// URL of the uploaded file (stringified URL).
    pub url: String,
}

/// Upload progress information emitted during file uploads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadProgress {
    pub file_name: String,
    pub bytes_sent: u64,
    pub total_bytes: u64,
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
pub(crate) struct RegisterRequest {
    pub(crate) username: String,
    pub(crate) password: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RegisterResponse {
    pub(crate) success: Option<bool>,
    pub(crate) token: Option<AuthToken>,
    pub(crate) message: Option<String>,
    pub(crate) description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct NodeResponse {
    pub(crate) success: Option<bool>,
    pub(crate) url: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) description: Option<String>,
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

#[derive(Debug, Deserialize)]
pub(crate) struct AlbumFilesResponse {
    pub(crate) success: Option<bool>,
    pub(crate) files: Option<Vec<AlbumFile>>,
    pub(crate) count: Option<u64>,
    pub(crate) albums: Option<HashMap<String, String>>,
    pub(crate) basedomain: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) description: Option<String>,
}

impl TryFrom<LoginResponse> for AuthToken {
    type Error = CyberdropError;

    fn try_from(response: LoginResponse) -> Result<Self, Self::Error> {
        response.token.ok_or(CyberdropError::MissingToken)
    }
}

impl TryFrom<RegisterResponse> for AuthToken {
    type Error = CyberdropError;

    fn try_from(body: RegisterResponse) -> Result<Self, Self::Error> {
        if body.success.unwrap_or(false) {
            return body.token.ok_or(CyberdropError::MissingToken);
        }

        let msg = body
            .description
            .or(body.message)
            .unwrap_or_else(|| "registration failed".to_string());

        Err(CyberdropError::Api(msg))
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

        let albums = body.albums.ok_or(CyberdropError::MissingField(
            "albums response missing albums",
        ))?;

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

impl TryFrom<AlbumFilesResponse> for AlbumFilesPage {
    type Error = CyberdropError;

    fn try_from(body: AlbumFilesResponse) -> Result<Self, Self::Error> {
        if !body.success.unwrap_or(false) {
            let msg = body
                .description
                .or(body.message)
                .unwrap_or_else(|| "failed to fetch album files".to_string());
            return Err(CyberdropError::Api(msg));
        }

        let files = body.files.ok_or(CyberdropError::MissingField(
            "album files response missing files",
        ))?;

        let count = body.count.ok_or(CyberdropError::MissingField(
            "album files response missing count",
        ))?;

        let base_domain = if files.is_empty() {
            match body.basedomain {
                Some(url) => Some(Url::parse(&url)?),
                None => None,
            }
        } else {
            let url = body.basedomain.ok_or(CyberdropError::MissingField(
                "album files response missing basedomain",
            ))?;
            Some(Url::parse(&url)?)
        };

        Ok(AlbumFilesPage {
            success: true,
            files,
            count,
            albums: body.albums.unwrap_or_default(),
            base_domain,
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
            let first = body.files.and_then(|mut files| files.pop()).ok_or(
                CyberdropError::MissingField("upload response missing files"),
            )?;
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

impl TryFrom<EditAlbumResponse> for EditAlbumResult {
    type Error = CyberdropError;

    fn try_from(body: EditAlbumResponse) -> Result<Self, Self::Error> {
        if !body.success.unwrap_or(false) {
            let msg = body
                .description
                .or(body.message)
                .unwrap_or_else(|| "edit album failed".to_string());
            return Err(CyberdropError::Api(msg));
        }

        if body.name.is_none() && body.identifier.is_none() {
            return Err(CyberdropError::MissingField(
                "edit album response missing name/identifier",
            ));
        }

        Ok(EditAlbumResult {
            name: body.name,
            identifier: body.identifier,
        })
    }
}
