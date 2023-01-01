use crate::auth::Claims;
use crate::server::{AuthRedirect, COOKIE_NAME};
use async_session::{MemoryStore, SessionStore};
use axum::{
    async_trait,
    extract::{rejection::TypedHeaderRejectionReason, FromRef, FromRequestParts, TypedHeader},
    http::{header, request::Parts},
    RequestPartsExt,
};

#[derive(Debug, Clone)]
pub struct Profile {
    inner: Claims,
}

impl Profile {
    pub fn profile(&self) -> &Claims {
        &self.inner
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for Profile
where
    MemoryStore: FromRef<S>,
    S: Send + Sync,
{
    // If anything goes wrong or no session is found, redirect to the auth page
    type Rejection = AuthRedirect;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = MemoryStore::from_ref(state);

        let cookies = parts
            .extract::<TypedHeader<headers::Cookie>>()
            .await
            .map_err(|e| match *e.name() {
                header::COOKIE => match e.reason() {
                    TypedHeaderRejectionReason::Missing => AuthRedirect,
                    _ => panic!("unexpected error getting Cookie header(s): {}", e),
                },
                _ => panic!("unexpected error getting cookies: {}", e),
            })?;
        let session_cookie = cookies.get(COOKIE_NAME).ok_or(AuthRedirect)?;

        let session = store
            .load_session(session_cookie.to_string())
            .await
            .unwrap()
            .ok_or(AuthRedirect)?;

        let profile = session.get::<Claims>("profile").ok_or(AuthRedirect)?;

        Ok(Profile { inner: profile })
    }
}
