use reqwest::{
    Client, Method, RequestBuilder, StatusCode, Url,
    header::{ACCEPT, ACCEPT_LANGUAGE, HeaderName},
    multipart::{Form, Part},
};
use serde::de::DeserializeOwned;

use crate::{AuthToken, ChunkFields, CyberdropError};

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

    pub(crate) async fn get_raw(&self, path: &str) -> Result<reqwest::Response, CyberdropError> {
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

    pub(crate) async fn get_json_with_header<T>(
        &self,
        path: &str,
        requires_auth: bool,
        header_name: &'static str,
        header_value: &'static str,
    ) -> Result<T, CyberdropError>
    where
        T: DeserializeOwned,
    {
        let builder = self
            .build_request(Method::GET, path, requires_auth)?
            .header(header_name, header_value);
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

    pub(crate) async fn post_chunk_url<T>(
        &self,
        url: Url,
        data: Vec<u8>,
        fields: ChunkFields,
    ) -> Result<T, CyberdropError>
    where
        T: DeserializeOwned,
    {
        let mut builder = self.build_request_url(Method::POST, url, true)?;
        if let Some(id) = fields.album_id {
            builder = builder.header("albumid", id);
        }
        builder = builder
            .header("X-Requested-With", "XMLHttpRequest")
            .header("striptags", "undefined")
            .header("Origin", "https://cyberdrop.cr")
            .header("Referer", "https://cyberdrop.cr/")
            .header("Cache-Control", "no-cache")
            .header("Pragma", "no-cache");

        let part = Part::bytes(data).file_name(fields.file_name.clone());
        let part = match part.mime_str(&fields.mime_type) {
            Ok(p) => p,
            Err(_) => Part::bytes(Vec::new()).file_name(fields.file_name.clone()),
        };

        let form = Form::new()
            .text("dzuuid", fields.uuid.clone())
            .text("dzchunkindex", fields.chunk_index.to_string())
            .text("dztotalfilesize", fields.total_size.to_string())
            .text("dzchunksize", fields.chunk_size.to_string())
            .text("dztotalchunkcount", fields.total_chunks.to_string())
            .text("dzchunkbyteoffset", fields.byte_offset.to_string())
            .part("files[]", part);

        let builder = builder.multipart(form);
        self.send_json(builder).await
    }

    pub(crate) async fn post_json_with_upload_headers_url<B, T>(
        &self,
        url: Url,
        body: &B,
    ) -> Result<T, CyberdropError>
    where
        B: serde::Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let builder = self
            .build_request_url(Method::POST, url, true)?
            .header("X-Requested-With", "XMLHttpRequest")
            .header("striptags", "undefined")
            .header("Origin", "https://cyberdrop.cr")
            .header("Referer", "https://cyberdrop.cr/")
            .header("Cache-Control", "no-cache")
            .header("Pragma", "no-cache")
            .json(body);

        self.send_json(builder).await
    }

    pub(crate) async fn post_single_upload_url<T>(
        &self,
        url: Url,
        form: Form,
        album_id: Option<u64>,
    ) -> Result<T, CyberdropError>
    where
        T: DeserializeOwned,
    {
        let mut builder = self.build_request_url(Method::POST, url, true)?;
        if let Some(id) = album_id {
            builder = builder.header("albumid", id);
        }
        builder = builder
            .header("X-Requested-With", "XMLHttpRequest")
            .header("striptags", "undefined")
            .header("Origin", "https://cyberdrop.cr")
            .header("Referer", "https://cyberdrop.cr/")
            .header("Cache-Control", "no-cache")
            .header("Pragma", "no-cache");

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
        self.build_request_url(method, url, requires_auth)
    }

    fn build_request_url(
        &self,
        method: Method,
        url: Url,
        requires_auth: bool,
    ) -> Result<RequestBuilder, CyberdropError> {
        let builder = self
            .client
            .request(method, url)
            .header(ACCEPT, "application/json, text/plain, */*")
            .header(ACCEPT_LANGUAGE, "nl,en-US;q=0.9,en;q=0.8");

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
        let builder = builder.header(HeaderName::from_static("token"), token.as_str());

        builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transport_with_token(token: &str) -> Transport {
        Transport::new(
            Client::new(),
            Url::parse("https://example.test/root/").unwrap(),
            Some(AuthToken::new(token)),
        )
    }

    #[test]
    fn join_path_appends_relative_segment() {
        let transport = transport_with_token("abc");
        let url = transport.join_path("api/v1").unwrap();
        assert_eq!(url.as_str(), "https://example.test/root/api/v1");
    }

    #[test]
    fn build_request_requires_auth_token() {
        let transport = Transport::new(
            Client::new(),
            Url::parse("https://example.test/").unwrap(),
            None,
        );

        let err = transport
            .build_request(Method::GET, "api/secure", true)
            .unwrap_err();
        matches!(err, CyberdropError::MissingAuthToken);
    }

    #[test]
    fn build_request_attaches_auth_headers() {
        let transport = transport_with_token("secret");
        let builder = transport
            .build_request(Method::GET, "api/secure", true)
            .unwrap();
        let request = builder.build().unwrap();
        let headers = request.headers();
        assert_eq!(headers.get("token").unwrap(), "secret");
    }

    #[test]
    fn build_request_does_not_attach_headers_when_not_required() {
        let transport = transport_with_token("secret");
        let builder = transport
            .build_request(Method::GET, "api/public", false)
            .unwrap();
        let request = builder.build().unwrap();
        let headers = request.headers();
        assert!(!headers.contains_key("token"));
    }

    #[test]
    fn map_status_classifies_errors() {
        assert!(Transport::map_status(StatusCode::OK).is_ok());

        let auth_err = Transport::map_status(StatusCode::UNAUTHORIZED).unwrap_err();
        matches!(
            auth_err,
            CyberdropError::AuthenticationFailed(StatusCode::UNAUTHORIZED)
        );

        let forbidden = Transport::map_status(StatusCode::FORBIDDEN).unwrap_err();
        matches!(
            forbidden,
            CyberdropError::AuthenticationFailed(StatusCode::FORBIDDEN)
        );

        let server_err = Transport::map_status(StatusCode::INTERNAL_SERVER_ERROR).unwrap_err();
        matches!(
            server_err,
            CyberdropError::RequestFailed(StatusCode::INTERNAL_SERVER_ERROR)
        );
    }
}
