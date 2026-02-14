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

    let client = CyberdropClient::builder().build()?;
    let token = client.register(username, password).await?;

    println!("Registration succeeded. Token: {}", token.as_str());
    Ok(())
}
