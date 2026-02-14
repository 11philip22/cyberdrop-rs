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

fn parse_bool(s: &str, name: &str) -> bool {
    s.parse::<bool>()
        .unwrap_or_else(|_| panic!("{name} must be 'true' or 'false'"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let username = take_arg_or_env(&mut args, "CYBERDROP_USERNAME", "username");
    let password = take_arg_or_env(&mut args, "CYBERDROP_PASSWORD", "password");

    let album_id = args
        .next()
        .expect(
            "usage: cargo run --example edit_album -- <username> <password> <album_id> <name> <description> <download:true|false> <public:true|false> <request_new_link:true|false>\n\
or:    cargo run --example edit_album -- <album_id> <name> <description> <download:true|false> <public:true|false> <request_new_link:true|false> (with env vars)",
        )
        .parse::<u64>()
        .expect("album_id must be a number");

    let name = args.next().expect("missing <name>");
    let description = args.next().expect("missing <description>");

    let download = parse_bool(&args.next().expect("missing <download>"), "download");
    let public = parse_bool(&args.next().expect("missing <public>"), "public");
    let request_new_link = parse_bool(
        &args.next().expect("missing <request_new_link>"),
        "request_new_link",
    );

    let client = CyberdropClient::builder().build()?;
    let token = client.login(username, password).await?;
    let client = client.with_auth_token(token.into_string());

    let edited = client
        .edit_album(
            album_id,
            name,
            description,
            download,
            public,
            request_new_link,
        )
        .await?;

    if let Some(identifier) = edited.identifier.as_deref() {
        println!("Updated album {album_id}; new identifier: {identifier}");
    } else if let Some(name) = edited.name.as_deref() {
        println!("Updated album {album_id}; name: {name}");
    } else {
        // The library currently treats this as an error, but keep output defensive.
        println!("Updated album {album_id}");
    }

    Ok(())
}
