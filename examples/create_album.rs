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
    let album_name = args.next().unwrap_or_else(|| "test".to_string());
    let description = args.next();

    let client = CyberdropClient::builder().build()?;
    let token = client.login(username, password).await?;
    let client = client.with_auth_token(token.into_string());

    match client.create_album(album_name, description).await {
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
