use std::collections::{HashMap, HashSet};

use reqwest::Url;
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

impl CyberdropClient {
    pub async fn get_album_by_id(&self, album_id: u64) -> Result<Album, CyberdropError> {
        let albums = self.list_albums().await?;
        albums
            .albums
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
    pub async fn list_albums(&self) -> Result<AlbumsList, CyberdropError> {
        let response: AlbumsResponse = self
            .transport
            .get_json_with_header("api/albums", true, "Simple", "1")
            .await?;
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
        let mut albums = HashMap::new();
        let mut base_domain = None::<Url>;
        let mut seen = HashSet::<u64>::new();

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

            if let Some(total) = total_count
                && all_files.len() as u64 >= total
            {
                break;
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
        Ok(identifier.to_string())
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
