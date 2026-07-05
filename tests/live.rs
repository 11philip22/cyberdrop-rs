#![cfg(feature = "live-tests")]

use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cyberdrop_client::{
    Album, AlbumFile, AlbumFilesPage, AlbumsList, AuthToken, CyberdropClient,
    CyberdropClientBuilder, CyberdropError, EditAlbumResult, Permissions, TokenVerification,
    UploadProgress, UploadedFile,
};
use tokio::sync::OnceCell;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Debug)]
struct LiveAccount {
    username: String,
    password: String,
    token: String,
    client: CyberdropClient,
}

static LIVE_ACCOUNT: OnceCell<LiveAccount> = OnceCell::const_new();

async fn live_account() -> TestResult<&'static LiveAccount> {
    LIVE_ACCOUNT
        .get_or_try_init(|| async {
            let suffix =
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() % 1_000_000_000_000_000;
            let username = format!("cdlive{suffix}");
            let password = format!("CdLive{suffix}Pass1");

            let client = CyberdropClient::builder().build()?;
            let token = client.register(&username, &password).await?.into_string();
            let client = client.with_auth_token(token.clone());

            Ok::<_, Box<dyn Error + Send + Sync>>(LiveAccount {
                username,
                password,
                token,
                client,
            })
        })
        .await
}

fn temp_file(name: &str, contents: &[u8]) -> TestResult<PathBuf> {
    let path = std::env::temp_dir().join(name);
    std::fs::write(&path, contents)?;
    Ok(path)
}

#[tokio::test(flavor = "current_thread")]
async fn auth_builder_and_raw_get_surface() -> TestResult {
    let token = AuthToken::new("secret-token");
    assert_eq!(token.as_str(), "secret-token");
    assert_eq!(token.clone().into_string(), "secret-token");
    assert!(!format!("{token:?}").contains("secret-token"));

    let unauth = CyberdropClient::new()?;
    assert_eq!(unauth.auth_token(), None);
    let authed = unauth.clone().with_auth_token("local-token");
    assert_eq!(authed.auth_token(), Some("local-token"));

    let built = CyberdropClientBuilder::new()
        .user_agent("cyberdrop-client-live-test")
        .timeout(Duration::from_secs(30))
        .auth_token("builder-token")
        .build()?;
    assert_eq!(built.auth_token(), Some("builder-token"));

    let account = live_account().await?;

    let logged_in: AuthToken = CyberdropClient::builder()
        .build()?
        .login(&account.username, &account.password)
        .await?;
    assert!(!logged_in.as_str().is_empty());

    let verified: TokenVerification = account.client.verify_token(&account.token).await?;
    assert!(verified.success);
    assert_eq!(verified.username, account.username);
    let permissions: Permissions = verified.permissions;
    assert!(permissions.user);

    let response = account.client.get("api/albums").await?;
    assert!(response.status().is_success());

    let err = CyberdropError::MissingAuthToken;
    assert!(err.to_string().contains("auth token"));

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn album_surface() -> TestResult {
    let account = live_account().await?;

    let suffix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let album_id = account
        .client
        .create_album(
            format!("cyberdrop-client live {suffix}"),
            Some("created by live sdk test"),
        )
        .await?;

    let albums: AlbumsList = account.client.list_albums().await?;
    assert!(albums.success);
    assert!(albums.albums.iter().any(|album| album.id == album_id));

    let album: Album = account.client.get_album_by_id(album_id).await?;
    assert_eq!(album.id, album_id);

    let page: AlbumFilesPage = account.client.list_album_files_page(album_id, 0).await?;
    assert!(page.success);
    let all_files: AlbumFilesPage = account.client.list_album_files(album_id).await?;
    assert!(all_files.success);

    let edited: EditAlbumResult = account
        .client
        .edit_album(
            album_id,
            format!("cyberdrop-client live edited {suffix}"),
            "edited by live sdk test",
            true,
            true,
            false,
        )
        .await?;
    assert!(edited.name.is_some() || edited.identifier.is_some());

    let identifier = account.client.request_new_album_link(album_id).await?;
    assert!(!identifier.is_empty());

    account
        .client
        .set_album_name(album_id, format!("cyberdrop-client live renamed {suffix}"))
        .await?;
    account
        .client
        .set_album_description(album_id, "description changed by live sdk test")
        .await?;
    account.client.set_album_download(album_id, false).await?;
    account.client.set_album_public(album_id, false).await?;

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn upload_surface() -> TestResult {
    let account = live_account().await?;

    let suffix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let album_id = account
        .client
        .create_album(
            format!("cyberdrop-client upload live {suffix}"),
            Some("created by upload live sdk test"),
        )
        .await?;

    let upload_url = account.client.get_upload_url().await?;
    assert_eq!(upload_url.scheme(), "https");

    let first_path = temp_file(
        &format!("cyberdrop-client-live-{suffix}-a.txt"),
        b"small live sdk upload\n",
    )?;
    let uploaded: UploadedFile = account
        .client
        .upload_file(&first_path, Some(album_id))
        .await?;
    assert!(!uploaded.name.is_empty());
    assert!(uploaded.url.starts_with("https://"));

    let progress_bytes = Arc::new(AtomicU64::new(0));
    let seen_progress = Arc::clone(&progress_bytes);
    let second_path = temp_file(
        &format!("cyberdrop-client-live-{suffix}-b.txt"),
        b"small live sdk upload with progress\n",
    )?;
    let uploaded_with_progress: UploadedFile = account
        .client
        .upload_file_with_progress(
            &second_path,
            Some(album_id),
            move |progress: UploadProgress| {
                seen_progress.store(progress.bytes_sent, Ordering::SeqCst);
            },
        )
        .await?;
    assert!(!uploaded_with_progress.url.is_empty());
    assert!(progress_bytes.load(Ordering::SeqCst) > 0);

    let page: AlbumFilesPage = account.client.list_album_files_page(album_id, 0).await?;
    assert!(page.files.len() >= 2);
    let file: &AlbumFile = &page.files[0];
    assert!(!file.name.is_empty());

    let _ = std::fs::remove_file(first_path);
    let _ = std::fs::remove_file(second_path);

    Ok(())
}
