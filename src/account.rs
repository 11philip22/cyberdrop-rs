use serde::{Deserialize, Serialize};

use crate::CyberdropError;
use crate::client::CyberdropClient;
use crate::token::AuthToken;

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

impl CyberdropClient {
    /// Authenticate and retrieve a token.
    ///
    /// The returned token can be installed on a client via [`CyberdropClient::with_auth_token`]
    /// or [`crate::CyberdropClientBuilder::auth_token`].
    ///
    /// # Errors
    ///
    /// - [`CyberdropError::AuthenticationFailed`] / [`CyberdropError::RequestFailed`] for non-2xx statuses
    /// - [`CyberdropError::MissingToken`] if the response body omits the token field
    /// - [`CyberdropError::Http`] for transport failures (including timeouts)
    pub async fn login(
        &self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<AuthToken, CyberdropError> {
        let payload = LoginRequest {
            username: username.into(),
            password: password.into(),
        };

        let response: LoginResponse = self
            .transport
            .post_json("api/login", &payload, false)
            .await?;

        AuthToken::try_from(response)
    }

    /// Register a new account and retrieve a token.
    ///
    /// The returned token can be installed on a client via [`CyberdropClient::with_auth_token`]
    /// or [`crate::CyberdropClientBuilder::auth_token`].
    ///
    /// Note: the API returns HTTP 200 even for validation failures; this method converts
    /// `{"success":false,...}` responses into [`CyberdropError::Api`].
    ///
    /// # Errors
    ///
    /// - [`CyberdropError::Api`] if the API reports a validation failure (e.g. username taken)
    /// - [`CyberdropError::MissingToken`] if the response body omits the token field on success
    /// - [`CyberdropError::Http`] for transport failures (including timeouts)
    pub async fn register(
        &self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<AuthToken, CyberdropError> {
        let payload = RegisterRequest {
            username: username.into(),
            password: password.into(),
        };

        let response: RegisterResponse = self
            .transport
            .post_json("api/register", &payload, false)
            .await?;

        AuthToken::try_from(response)
    }

    /// Verify a token and fetch associated permissions.
    ///
    /// This request does not require the client to be authenticated; the token to verify is
    /// supplied in the request body.
    ///
    /// # Errors
    ///
    /// - [`CyberdropError::AuthenticationFailed`] / [`CyberdropError::RequestFailed`] for non-2xx statuses
    /// - [`CyberdropError::MissingField`] if expected fields are missing in the response body
    /// - [`CyberdropError::Http`] for transport failures (including timeouts)
    pub async fn verify_token(
        &self,
        token: impl Into<String>,
    ) -> Result<TokenVerification, CyberdropError> {
        let payload = VerifyTokenRequest {
            token: token.into(),
        };

        let response: VerifyTokenResponse = self
            .transport
            .post_json("api/tokens/verify", &payload, false)
            .await?;

        TokenVerification::try_from(response)
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
