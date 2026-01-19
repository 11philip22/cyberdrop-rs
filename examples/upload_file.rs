use cyberdrop_client::CyberdropClient;

fn take_arg_or_env(args: &mut impl Iterator<Item = String>, env_key: &str, arg_name: &str) -> String {
    args.next()
        .or_else(|| std::env::var(env_key).ok())
        .unwrap_or_else(|| panic!("provide {} as arg or set {}", arg_name, env_key))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let username = take_arg_or_env(&mut args, "CYBERDROP_USERNAME", "username");
    let password = take_arg_or_env(&mut args, "CYBERDROP_PASSWORD", "password");

    let file_path = args
        .next()
        .expect("usage: cargo run --example upload_file -- <username> <password> <path> [album_id]");

    let album_id = match args.next() {
        Some(v) => Some(v.parse::<u64>().expect("album_id must be a number")),
        None => std::env::var("CYBERDROP_ALBUM_ID")
            .ok()
            .and_then(|v| v.parse::<u64>().ok()),
    };

    let client = CyberdropClient::builder().build()?;
    let token = client.login(username, password).await?;
    let client = client.with_auth_token(token.into_string());

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
