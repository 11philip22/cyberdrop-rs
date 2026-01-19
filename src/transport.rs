use reqwest::{multipart::Form, Client, Method, RequestBuilder, StatusCode, Url};
use serde::de::DeserializeOwned;

use crate::{AuthToken, CyberdropError};

#[derive(Debug, Clone)]
pub(crate) struct Transport {
    pub(crate) client: Client,
    pub(crate) base_url: Url,
    pub(crate) auth_token: Option<AuthToken>,
}

impl Transport {
    pub(crate) fn new(client: Client, base_url: Url, auth_token: Option<AuthToken>) -> Self {
        Self {
            client,
            base_url,
            auth_token,
        }
    }

    pub(crate) fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub(crate) fn auth_token(&self) -> Option<&str> {
        self.auth_token.as_ref().map(AuthToken::as_str)
    }

    pub(crate) fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(AuthToken::new(token));
        self
    }

    pub(crate) async fn get_raw(
        &self,
        path: &str,
    ) -> Result<reqwest::Response, CyberdropError> {
        let builder = self.apply_auth_if_present(self.client.get(self.join_path(path)?));
        builder.send().await.map_err(CyberdropError::from)
    }

    pub(crate) async fn get_json<T>(
        &self,
        path: &str,
        requires_auth: bool,
    ) -> Result<T, CyberdropError>
    where
        T: DeserializeOwned,
    {
        let builder = self.build_request(Method::GET, path, requires_auth)?;
        self.send_json(builder).await
    }

    pub(crate) async fn post_json<B, T>(
        &self,
        path: &str,
        body: &B,
        requires_auth: bool,
    ) -> Result<T, CyberdropError>
    where
        B: serde::Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let builder = self
            .build_request(Method::POST, path, requires_auth)?
            .json(body);
        self.send_json(builder).await
    }

    pub(crate) async fn post_multipart<T>(
        &self,
        path: &str,
        form: Form,
        album_id: Option<u64>,
    ) -> Result<T, CyberdropError>
    where
        T: DeserializeOwned,
    {
        let mut builder = self.build_request(Method::POST, path, true)?;
        if let Some(id) = album_id {
            builder = builder.header("albumid", id);
        }
        let builder = builder.multipart(form);
        self.send_json(builder).await
    }

    async fn send_json<T>(&self, builder: RequestBuilder) -> Result<T, CyberdropError>
    where
        T: DeserializeOwned,
    {
        let response = builder.send().await?;
        Self::map_status(response.status())?;
        Ok(response.json().await?)
    }

    fn build_request(
        &self,
        method: Method,
        path: &str,
        requires_auth: bool,
    ) -> Result<RequestBuilder, CyberdropError> {
        let url = self.join_path(path)?;
        let builder = self.client.request(method, url);

        if requires_auth {
            self.apply_auth(builder)
        } else {
            Ok(builder)
        }
    }

    fn map_status(status: StatusCode) -> Result<(), CyberdropError> {
        if status.is_success() {
            return Ok(());
        }

        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            Err(CyberdropError::AuthenticationFailed(status))
        } else {
            Err(CyberdropError::RequestFailed(status))
        }
    }

    pub(crate) fn join_path(&self, path: &str) -> Result<Url, CyberdropError> {
        Ok(self.base_url.join(path)?)
    }

    fn apply_auth(&self, builder: RequestBuilder) -> Result<RequestBuilder, CyberdropError> {
        let token = self
            .auth_token
            .as_ref()
            .ok_or(CyberdropError::MissingAuthToken)?;

        Ok(Self::attach_token(builder, token))
    }

    fn apply_auth_if_present(&self, builder: RequestBuilder) -> RequestBuilder {
        match &self.auth_token {
            Some(token) => Self::attach_token(builder, token),
            None => builder,
        }
    }

    fn attach_token(builder: RequestBuilder, token: &AuthToken) -> RequestBuilder {
        builder
            .bearer_auth(token.as_str())
            .header("Token", token.as_str())
            .header("token", token.as_str())
    }
}
