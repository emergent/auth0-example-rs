use serde::Deserialize;

pub mod auth;
pub mod extractor;
pub mod handler;
pub mod server;

#[derive(Deserialize, Clone, Debug)]
pub struct Auth0Config {
    domain: String,
    client_id: String,
    client_secret: String,
    base_url: String,
}
