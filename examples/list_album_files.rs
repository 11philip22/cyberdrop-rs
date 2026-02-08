use cyberdrop_client::CyberdropClient;

fn take_arg_or_env(
    args: &mut impl Iterator<Item = String>,
    env_key: &str,
    arg_name: &str,
) -> String {
    args.next()
        .or_else(|| std::env::var(env_key).ok())
        .unwrap_or_else(|| panic!("provide {} as arg or set {}", arg_name, env_key))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let username = take_arg_or_env(&mut args, "CYBERDROP_USERNAME", "username");
    let password = take_arg_or_env(&mut args, "CYBERDROP_PASSWORD", "password");

    let album_id = args
        .next()
        .expect("usage: cargo run --example list_album_files -- <username> <password> <album_id>")
        .parse::<u64>()
        .expect("album_id must be a number");

    let client = CyberdropClient::builder().build()?;
    let token = client.login(username, password).await?;
    let client = client.with_auth_token(token.into_string());

    let page = client.list_album_files(album_id).await?;
    println!(
        "Album {album_id}: returned {} files (total count: {})",
        page.files.len(),
        page.count
    );

    for file in page.files.iter() {
        println!(
            "- {} (id: {}, size: {}, slug: {})",
            file.name, file.id, file.size, file.slug
        );
    }

    println!("Base domain: {}", page.base_domain);

    Ok(())
}
