use crate::auth::Authenticator;
use axum::{
    extract::State,
    response::{IntoResponse, Redirect},
};
use tracing::instrument;

#[instrument]
pub async fn login(State(auth): State<Authenticator>) -> impl IntoResponse {
    let auth_url = auth.login_redirect_url().await;
    Redirect::to(auth_url.as_ref())
}
