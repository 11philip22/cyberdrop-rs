use cyberdrop_client::CyberdropClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = std::env::var("CYBERDROP_TOKEN").expect("CYBERDROP_TOKEN env var not set");

    let client = CyberdropClient::builder().auth_token(token).build()?;
    let albums = client.list_albums().await?;

    println!("Found {} albums:", albums.albums.len());
    for album in albums.albums.iter() {
        println!(
            "- {} (id: {}, files: {}, public: {})",
            album.name, album.id, album.files, album.public
        );
    }

    if let Some(home) = albums.home_domain {
        println!("Home domain: {}", home);
    }

    Ok(())
}
