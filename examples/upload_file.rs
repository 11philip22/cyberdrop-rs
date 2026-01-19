use cyberdrop_client::CyberdropClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = std::env::var("CYBERDROP_TOKEN").expect("CYBERDROP_TOKEN env var not set");

    let mut args = std::env::args().skip(1);
    let file_path = args
        .next()
        .expect("usage: cargo run --example upload_file -- <path> [album_id]");

    let album_id = match args.next() {
        Some(v) => Some(v.parse::<u64>().expect("album_id must be a number")),
        None => std::env::var("CYBERDROP_ALBUM_ID")
            .ok()
            .and_then(|v| v.parse::<u64>().ok()),
    };

    let client = CyberdropClient::builder().auth_token(token).build()?;
    let uploaded = client.upload_file(file_path, album_id).await?;

    let target = album_id
        .map(|id| format!("album {}", id))
        .unwrap_or_else(|| "default target".to_string());

    println!(
        "Uploaded to {}: {} at {}",
        target, uploaded.name, uploaded.url
    );
    Ok(())
}
