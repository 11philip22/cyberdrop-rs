use serde::Deserialize;
use serde::de;

/// File metadata as returned by the album listing endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AlbumFile {
    /// File numeric ID.
    pub id: u64,
    /// Display name.
    pub name: String,
    /// Uploader user ID as returned by the service.
    #[serde(rename = "userid", deserialize_with = "de_string_or_number")]
    pub user_id: String,
    /// File size in bytes.
    #[serde(deserialize_with = "de_u64_or_string")]
    pub size: u64,
    /// Service-provided timestamp value.
    pub timestamp: u64,
    /// Last visited timestamp, if returned by the service.
    #[serde(rename = "last_visited_at")]
    pub last_visited_at: Option<String>,
    /// Service-provided file slug.
    pub slug: String,
    /// Base domain for file media (for example, `https://sun-i.cyberdrop.cr`).
    pub image: String,
    /// Nullable expiry date as returned by the service.
    pub expirydate: Option<String>,
    /// Album ID as returned by the service.
    #[serde(rename = "albumid", deserialize_with = "de_string_or_number")]
    pub album_id: String,
    /// File extension name as returned by the service.
    pub extname: String,
    /// Thumbnail path relative to `image` (for example, `thumbs/<...>.png`).
    #[serde(default)]
    pub thumb: String,
}

fn de_string_or_number<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match StringOrNumber::deserialize(deserializer)? {
        StringOrNumber::String(v) => v,
        StringOrNumber::U64(v) => v.to_string(),
        StringOrNumber::I64(v) => v.to_string(),
    })
}

fn de_u64_or_string<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match StringOrNumber::deserialize(deserializer)? {
        StringOrNumber::String(v) => v.parse::<u64>().map_err(de::Error::custom),
        StringOrNumber::U64(v) => Ok(v),
        StringOrNumber::I64(v) => {
            u64::try_from(v).map_err(|_| de::Error::custom("negative value not allowed"))
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StringOrNumber {
    String(String),
    U64(u64),
    I64(i64),
}
