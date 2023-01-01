use crate::auth::Authenticator;
use crate::server::COOKIE_NAME;
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

#[instrument]
pub async fn callback(
    Query(query): Query<AuthRequest>,
    State(store): State<MemoryStore>,
    State(auth): State<Authenticator>,
) -> impl IntoResponse {
    let (access_token, claims) = auth.verify_code(query.state, query.code).await.unwrap();

    // Create a new session filled with user data
    let mut session = Session::new();
    session.insert("access_token", access_token).unwrap();
    session.insert("profile", claims).unwrap();

    // Store session and get corresponding cookie
    let cookie = store.store_session(session).await.unwrap().unwrap();

    // Build the cookie
    let cookie = format!("{}={}; SameSite=Lax; Path=/", COOKIE_NAME, cookie);

    // Set cookie
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie.parse().unwrap());

    tracing::debug!("{:?}", &headers);

    (headers, Redirect::to("/user"))
}
