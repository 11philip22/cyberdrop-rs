use serde::{Deserialize, Serialize};

use crate::CyberdropError;
use crate::client::CyberdropClient;
use crate::files::AlbumFile;

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

/// Files returned by the album listing endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlbumFiles {
    /// Files collected for the album.
    pub files: Vec<AlbumFile>,
    /// Total number of files in the album.
    pub count: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateAlbumRequest {
    pub(crate) name: String,
    pub(crate) description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateAlbumResponse {
    pub(crate) success: Option<bool>,
    pub(crate) id: Option<u64>,
    pub(crate) message: Option<String>,
    pub(crate) description: Option<String>,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AlbumsResponse {
    pub(crate) success: Option<bool>,
    pub(crate) albums: Option<Vec<Album>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AlbumFilesResponse {
    pub(crate) success: Option<bool>,
    pub(crate) files: Option<Vec<AlbumFile>>,
    pub(crate) count: Option<u64>,
    pub(crate) message: Option<String>,
    pub(crate) description: Option<String>,
}

impl CyberdropClient {
    pub async fn get_album_by_id(&self, album_id: u64) -> Result<Album, CyberdropError> {
        let albums = self.list_albums().await?;
        albums
            .into_iter()
            .find(|album| album.id == album_id)
            .ok_or(CyberdropError::AlbumNotFound(album_id))
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
    pub async fn list_albums(&self) -> Result<Vec<Album>, CyberdropError> {
        let response: AlbumsResponse = self
            .get_json_with_header("api/albums", true, "Simple", "1")
            .await?;

        if !response.success.unwrap_or(false) {
            return Err(CyberdropError::Api("failed to fetch albums".into()));
        }

        response.albums.ok_or(CyberdropError::MissingField(
            "albums response missing albums",
        ))
    }

    /// List all files in an album ("folder") by iterating pages until exhaustion.
    ///
    /// Starts at `page = 0` and stops when:
    /// - enough files have been collected to satisfy the API-reported `count`, or
    /// - a page returns zero files.
    ///
    /// Requires an auth token (see [`CyberdropClient::with_auth_token`]).
    ///
    /// # Returns
    ///
    /// An [`AlbumFiles`] value containing all collected files and the API-reported total count.
    ///
    /// # Errors
    ///
    /// - [`CyberdropError::MissingAuthToken`] if the client has no configured token
    /// - [`CyberdropError::AuthenticationFailed`] / [`CyberdropError::RequestFailed`] for non-2xx statuses
    /// - [`CyberdropError::Api`] for service-reported failures
    /// - [`CyberdropError::MissingField`] if expected fields are missing in the response body
    /// - [`CyberdropError::Http`] for transport failures (including timeouts)
    pub async fn list_album_files(&self, album_id: u64) -> Result<AlbumFiles, CyberdropError> {
        let mut page = 0u64;
        let mut all_files = Vec::new();
        let mut total_count = None::<u64>;

        loop {
            let path = format!("api/album/{album_id}/{page}");
            let response: AlbumFilesResponse = self.get_json(&path, true).await?;

            if !response.success.unwrap_or(false) {
                let msg = response
                    .description
                    .or(response.message)
                    .unwrap_or_else(|| "failed to fetch album files".to_string());
                return Err(CyberdropError::Api(msg));
            }

            let mut res = AlbumFiles {
                files: response.files.ok_or(CyberdropError::MissingField(
                    "album files response missing files",
                ))?,
                count: response.count.ok_or(CyberdropError::MissingField(
                    "album files response missing count",
                ))?,
            };

            if total_count.is_none() {
                total_count = Some(res.count);
            }

            if res.files.is_empty() {
                break;
            }

            all_files.append(&mut res.files);

            if let Some(total) = total_count
                && all_files.len() as u64 >= total
            {
                break;
            }

            page += 1;
        }

        Ok(AlbumFiles {
            files: all_files,
            count: total_count.unwrap_or(0),
        })
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

        let response: CreateAlbumResponse = self.post_json("api/albums", &payload, true).await?;

        if response.success.unwrap_or(false) {
            return response.id.ok_or(CyberdropError::MissingField(
                "create album response missing id",
            ));
        }

        let msg = response
            .description
            .or(response.message)
            .unwrap_or_else(|| "create album failed".to_string());

        if msg.to_lowercase().contains("already an album") {
            Err(CyberdropError::AlbumAlreadyExists(msg))
        } else {
            Err(CyberdropError::Api(msg))
        }
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

        let response: EditAlbumResponse = self.post_json("api/albums/edit", &payload, true).await?;

        if !response.success.unwrap_or(false) {
            let msg = response
                .description
                .or(response.message)
                .unwrap_or_else(|| "edit album failed".to_string());
            return Err(CyberdropError::Api(msg));
        }

        if response.name.is_none() && response.identifier.is_none() {
            return Err(CyberdropError::MissingField(
                "edit album response missing name/identifier",
            ));
        }

        Ok(EditAlbumResult {
            name: response.name,
            identifier: response.identifier,
        })
    }
}
