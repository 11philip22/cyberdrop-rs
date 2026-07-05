use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_core::Stream;
use reqwest::{
    Body, Url,
    multipart::{Form, Part},
};
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::CyberdropError;
use crate::client::CyberdropClient;
use crate::config::CHUNK_SIZE;

/// Uploaded file metadata returned by [`crate::CyberdropClient::upload_file`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct UploadedFile {
    /// Name of the uploaded file.
    pub name: String,
    /// URL of the uploaded file (stringified URL).
    pub url: String,
}

/// Upload progress information emitted during file uploads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadProgress {
    pub file_name: String,
    pub bytes_sent: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct UploadResponse {
    pub(crate) success: Option<bool>,
    pub(crate) description: Option<String>,
    pub(crate) files: Option<Vec<UploadedFile>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct NodeResponse {
    pub(crate) success: Option<bool>,
    pub(crate) url: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ChunkResponse {
    pub(crate) success: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(crate) struct FinishFile {
    pub(crate) uuid: String,
    pub(crate) original: String,
    #[serde(rename = "type")]
    pub(crate) r#type: String,
    pub(crate) albumid: Option<u64>,
    pub(crate) filelength: Option<u64>,
    pub(crate) age: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct FinishChunksPayload {
    pub(crate) files: Vec<FinishFile>,
}

struct ProgressStream<S, F> {
    inner: S,
    bytes_sent: u64,
    total_bytes: u64,
    file_name: String,
    callback: F,
}

impl<S, F> ProgressStream<S, F>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Unpin,
    F: FnMut(UploadProgress) + Send,
{
    fn new(inner: S, total_bytes: u64, file_name: String, callback: F) -> Self {
        Self {
            inner,
            bytes_sent: 0,
            total_bytes,
            file_name,
            callback,
        }
    }
}

impl<S, F> Stream for ProgressStream<S, F>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Unpin,
    F: FnMut(UploadProgress) + Send,
{
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                this.bytes_sent = this.bytes_sent.saturating_add(bytes.len() as u64);
                (this.callback)(UploadProgress {
                    file_name: this.file_name.clone(),
                    bytes_sent: this.bytes_sent,
                    total_bytes: this.total_bytes,
                });
                Poll::Ready(Some(Ok(bytes)))
            }
            other => other,
        }
    }
}

impl<S, F> Unpin for ProgressStream<S, F>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Unpin,
    F: FnMut(UploadProgress) + Send,
{
}

struct PreparedUpload {
    file: File,
    file_name: String,
    mime: String,
    total_size: u64,
}

async fn prepare_upload_file(file_path: &Path) -> Result<PreparedUpload, CyberdropError> {
    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(CyberdropError::InvalidFileName)?
        .to_string();

    let mime = mime_guess::from_path(file_path)
        .first_raw()
        .unwrap_or("application/octet-stream")
        .to_string();

    let file = File::open(file_path).await?;
    let total_size = file.metadata().await?.len();

    Ok(PreparedUpload {
        file,
        file_name,
        mime,
        total_size,
    })
}

fn finish_chunks_url(mut upload_url: Url) -> Url {
    upload_url.set_path("/api/upload/finishchunks");
    upload_url
}

impl CyberdropClient {
    /// Fetch the upload node URL for the authenticated user.
    ///
    /// Requires an auth token (see [`CyberdropClient::with_auth_token`]).
    pub async fn get_upload_url(&self) -> Result<Url, CyberdropError> {
        let response: NodeResponse = self.get_json("api/node", true).await?;

        if !response.success.unwrap_or(false) {
            let msg = response
                .description
                .or(response.message)
                .unwrap_or_else(|| "failed to fetch upload node".to_string());
            return Err(CyberdropError::Api(msg));
        }

        let url = response
            .url
            .ok_or(CyberdropError::MissingField("node response missing url"))?;

        Ok(Url::parse(&url)?)
    }

    /// Upload a single file.
    ///
    /// Requires an auth token.
    ///
    /// Implementation notes:
    /// - Small files are streamed.
    /// - Large files are uploaded in chunks from disk.
    /// - Files larger than `95_000_000` bytes are uploaded in chunks.
    /// - If `album_id` is provided, it is sent as an `albumid` header on the chunk/single-upload
    ///   requests and included in the `finishchunks` payload.
    ///
    /// # Errors
    ///
    /// - [`CyberdropError::MissingAuthToken`] if the client has no configured token
    /// - [`CyberdropError::InvalidFileName`] if `file_path` does not have a valid UTF-8 file name
    /// - [`CyberdropError::Io`] if reading the file fails
    /// - [`CyberdropError::AuthenticationFailed`] / [`CyberdropError::RequestFailed`] for non-2xx statuses
    /// - [`CyberdropError::Api`] if the service reports an upload failure (including per-chunk failures)
    /// - [`CyberdropError::MissingField`] if expected fields are missing in the response body
    /// - [`CyberdropError::Http`] for transport failures (including timeouts)
    pub async fn upload_file(
        &self,
        file_path: impl AsRef<Path>,
        album_id: Option<u64>,
    ) -> Result<UploadedFile, CyberdropError> {
        self.upload_file_with_progress(file_path, album_id, |_| {})
            .await
    }

    /// Upload a single file and emit per-file progress updates.
    ///
    /// The `on_progress` callback is invoked as bytes are streamed or as chunks complete.
    pub async fn upload_file_with_progress<F>(
        &self,
        file_path: impl AsRef<Path>,
        album_id: Option<u64>,
        on_progress: F,
    ) -> Result<UploadedFile, CyberdropError>
    where
        F: FnMut(UploadProgress) + Send + 'static,
    {
        let prepared = prepare_upload_file(file_path.as_ref()).await?;
        let upload_url = self.get_upload_url().await?;

        if prepared.total_size <= CHUNK_SIZE {
            self.upload_small_file_with_progress(upload_url, prepared, album_id, on_progress)
                .await
        } else {
            self.upload_chunked_file_with_progress(upload_url, prepared, album_id, on_progress)
                .await
        }
    }

    async fn upload_small_file_with_progress<F>(
        &self,
        upload_url: Url,
        prepared: PreparedUpload,
        album_id: Option<u64>,
        on_progress: F,
    ) -> Result<UploadedFile, CyberdropError>
    where
        F: FnMut(UploadProgress) + Send + 'static,
    {
        let PreparedUpload {
            file,
            file_name,
            mime,
            total_size,
        } = prepared;

        let stream = ReaderStream::new(file);
        let progress_stream =
            ProgressStream::new(stream, total_size, file_name.clone(), on_progress);
        let body = Body::wrap_stream(progress_stream);
        let part = Part::stream_with_length(body, total_size).file_name(file_name.clone());
        let part = match part.mime_str(&mime) {
            Ok(p) => p,
            Err(_) => Part::bytes(Vec::new()).file_name(file_name),
        };
        let response: UploadResponse = self
            .post_upload_multipart_url(upload_url, Form::new().part("files[]", part), album_id)
            .await?;

        parse_upload_response(response)
    }

    async fn upload_chunked_file_with_progress<F>(
        &self,
        upload_url: Url,
        prepared: PreparedUpload,
        album_id: Option<u64>,
        mut on_progress: F,
    ) -> Result<UploadedFile, CyberdropError>
    where
        F: FnMut(UploadProgress) + Send + 'static,
    {
        let PreparedUpload {
            mut file,
            file_name,
            mime,
            total_size,
        } = prepared;

        let chunk_size = CHUNK_SIZE.min(total_size.max(1));
        let total_chunks = total_size.div_ceil(chunk_size).max(1);
        let uuid = Uuid::new_v4().to_string();
        let mut bytes_sent = 0u64;
        let mut chunk_index = 0u64;
        let mut buffer = Vec::with_capacity(chunk_size as usize);

        loop {
            buffer.clear();
            let read = file.read_buf(&mut buffer).await?;
            if read == 0 {
                break;
            }

            let part = Part::bytes(buffer).file_name(file_name.clone());
            let part = match part.mime_str(&mime) {
                Ok(p) => p,
                Err(_) => Part::bytes(Vec::new()).file_name(file_name.clone()),
            };
            let form = Form::new()
                .text("dzuuid", uuid.clone())
                .text("dzchunkindex", chunk_index.to_string())
                .text("dztotalfilesize", total_size.to_string())
                .text("dzchunksize", chunk_size.to_string())
                .text("dztotalchunkcount", total_chunks.to_string())
                .text("dzchunkbyteoffset", (chunk_index * chunk_size).to_string())
                .part("files[]", part);

            let response: ChunkResponse = self
                .post_upload_multipart_url(upload_url.clone(), form, album_id)
                .await?;

            if !response.success.unwrap_or(false) {
                return Err(CyberdropError::Api(format!("chunk {} failed", chunk_index)));
            }

            bytes_sent = bytes_sent.saturating_add(read as u64);
            on_progress(UploadProgress {
                file_name: file_name.clone(),
                bytes_sent,
                total_bytes: total_size,
            });
            chunk_index = chunk_index.saturating_add(1);
            buffer = Vec::with_capacity(chunk_size as usize);
        }

        self.finish_chunked_upload(upload_url, uuid, file_name, mime, album_id)
            .await
    }

    async fn finish_chunked_upload(
        &self,
        upload_url: Url,
        uuid: String,
        file_name: String,
        mime: String,
        album_id: Option<u64>,
    ) -> Result<UploadedFile, CyberdropError> {
        let payload = FinishChunksPayload {
            files: vec![FinishFile {
                uuid,
                original: file_name,
                r#type: mime,
                albumid: album_id,
                filelength: None,
                age: None,
            }],
        };
        let finish_url = finish_chunks_url(upload_url);

        let response: UploadResponse = self.post_upload_json_url(finish_url, &payload).await?;

        parse_upload_response(response)
    }
}

fn parse_upload_response(body: UploadResponse) -> Result<UploadedFile, CyberdropError> {
    if body.success.unwrap_or(false) {
        let first =
            body.files
                .and_then(|mut files| files.pop())
                .ok_or(CyberdropError::MissingField(
                    "upload response missing files",
                ))?;
        let url = Url::parse(&first.url)?;
        Ok(UploadedFile {
            name: first.name,
            url: url.to_string(),
        })
    } else {
        let msg = body
            .description
            .unwrap_or_else(|| "upload failed".to_string());
        Err(CyberdropError::Api(msg))
    }
}
