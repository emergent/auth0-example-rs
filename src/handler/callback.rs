use crate::auth::{AccessToken, Claims};
use crate::server::COOKIE_NAME;
use crate::{auth::Authenticator, server::InternalError};
use anyhow::Context;
use async_session::{MemoryStore, Session, SessionStore};
use axum::{
    extract::{Query, State},
    http::{header::SET_COOKIE, HeaderMap},
    response::{IntoResponse, Redirect},
};
use serde::Deserialize;
use tracing::instrument;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AuthRequest {
    code: String,
    state: String,
}

#[instrument(skip(store, auth))]
pub async fn callback(
    Query(query): Query<AuthRequest>,
    State(store): State<MemoryStore>,
    State(auth): State<Authenticator>,
) -> Result<impl IntoResponse, InternalError> {
    let (access_token, claims) = auth.verify_code(query.state, query.code).await?;
    let headers = save_and_get_cookie_header(&store, access_token, claims).await?;

    tracing::debug!("{:?}", &headers);

    Ok((headers, Redirect::to("/user")))
}

async fn save_and_get_cookie_header(
    store: &MemoryStore,
    access_token: AccessToken,
    claims: Claims,
) -> anyhow::Result<HeaderMap> {
    // Create a new session filled with user data
    let mut session = Session::new();
    session.insert("access_token", access_token)?;

    session.insert("profile", claims)?;

    // Store session and get corresponding cookie
    let cookie = store
        .store_session(session)
        .await?
        .context("cookie string not found")?;

    // Build the cookie
    let cookie = format!("{}={}; SameSite=Lax; Path=/", COOKIE_NAME, cookie);

    // Set cookie
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie.parse()?);

    Ok(headers)
}
