use auth0_example_rs::{server::start_server, Auth0Config};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "auth0_example_rs=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let auth0_config = envy::prefixed("AUTH0_")
        .from_env::<Auth0Config>()
        .expect("failed getting envs of Auth0.");

    start_server(auth0_config).await?;

    Ok(())
}
