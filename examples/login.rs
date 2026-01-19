use cyberdrop_client::CyberdropClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let username = std::env::var("CYBERDROP_USERNAME").expect("CYBERDROP_USERNAME env var not set");
    let password = std::env::var("CYBERDROP_PASSWORD").expect("CYBERDROP_PASSWORD env var not set");

    let client = CyberdropClient::builder().build()?;
    let token = client.login(username, password).await?;

    println!("Login succeeded. Token: {}", token.as_str());
    Ok(())
}
