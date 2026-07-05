use std::time::Duration;

pub(crate) const CHUNK_SIZE: u64 = 95_000_000;
pub(crate) const DEFAULT_BASE_URL: &str = "https://cyberdrop.cr/";
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
