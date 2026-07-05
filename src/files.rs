use serde::Deserialize;
use serde::de::{self, Visitor};
use std::fmt;

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
    #[serde(default)]
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
