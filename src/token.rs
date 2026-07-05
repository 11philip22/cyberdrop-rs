use std::fmt;

use serde::Deserialize;

/// Authentication token returned by [`crate::CyberdropClient::login`] and
/// [`crate::CyberdropClient::register`].
///
/// This type is `#[serde(transparent)]` and typically deserializes from a JSON string.
#[derive(Clone, PartialEq, Eq, Deserialize)]
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

impl fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthToken")
            .field("token", &"<redacted>")
            .finish()
    }
}
