use cyberdrop_client::CyberdropClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = std::env::var("CYBERDROP_TOKEN").expect("CYBERDROP_TOKEN env var not set");

    let client = CyberdropClient::builder().auth_token(token).build()?;
    match client.create_album("test", Some("test description")).await {
        Ok(album_id) => {
            println!("Created album with id {}", album_id);
            Ok(())
        }
        Err(err) => {
            eprintln!("Failed to create album: {err}");
            Err(err.into())
        }
    }
}
