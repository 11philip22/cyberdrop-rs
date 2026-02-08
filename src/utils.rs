use std::string::String;

pub(crate) fn default_user_agent() -> String {
    // Match a browser UA; the service appears to expect browser-like clients.
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0".into()
}

