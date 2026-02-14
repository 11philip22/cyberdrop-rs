use cyberdrop_client::CyberdropClient;

fn take_arg_or_env(
    args: &mut impl Iterator<Item = String>,
    env_key: &str,
    arg_name: &str,
) -> String {
    if let Ok(value) = std::env::var(env_key) {
        return value;
    }

    args.next()
        .unwrap_or_else(|| panic!("provide {} as arg or set {}", arg_name, env_key))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let username = take_arg_or_env(&mut args, "CYBERDROP_USERNAME", "username");
    let password = take_arg_or_env(&mut args, "CYBERDROP_PASSWORD", "password");

    let album_id = args
        .next()
        .expect(
            "usage: cargo run --example request_new_album_link -- <username> <password> <album_id>\n\
or:    cargo run --example request_new_album_link -- <album_id> (with env vars)",
        )
        .parse::<u64>()
        .expect("album_id must be a number");

    let client = CyberdropClient::builder().build()?;
    let token = client.login(username, password).await?;
    let client = client.with_auth_token(token.into_string());

    let url = client.request_new_album_link(album_id).await?;
    println!("Requested new link for album {album_id}; url: {url}");

    Ok(())
}
