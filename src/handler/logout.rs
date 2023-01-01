use crate::auth::Authenticator;
use axum::{
    extract::State,
    response::{IntoResponse, Redirect},
};
use tracing::instrument;

#[instrument]
pub async fn logout(State(auth): State<Authenticator>) -> impl IntoResponse {
    let logout_url = auth.logout_redirect_url().await;
    Redirect::to(logout_url.as_ref())
}
