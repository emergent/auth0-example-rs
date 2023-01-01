use crate::{auth::Authenticator, server::InternalError};
use axum::{
    extract::State,
    response::{IntoResponse, Redirect},
};
use tracing::instrument;

#[instrument]
pub async fn logout(State(auth): State<Authenticator>) -> Result<impl IntoResponse, InternalError> {
    let logout_url = auth.logout_redirect_url().await;
    Ok(Redirect::to(logout_url.as_ref()))
}
