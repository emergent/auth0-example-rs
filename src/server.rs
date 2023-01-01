use crate::{auth::Authenticator, handler, Auth0Config};
use async_session::MemoryStore;
use axum::{
    body::Bytes,
    extract::FromRef,
    http::{HeaderMap, Request},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use axum_extra::routing::SpaRouter;
use std::{net::SocketAddr, time::Duration};
use tower_http::{classify::ServerErrorsFailureClass, trace::TraceLayer};
use tracing::Span;

pub const COOKIE_NAME: &str = "auth-session";

pub async fn start_server(config: Auth0Config) -> anyhow::Result<()> {
    // `MemoryStore` is just used as an example. Don't use this in production.
    let store = MemoryStore::new();
    let authenticator = Authenticator::discover(config).await?;
    let app_state = AppState {
        authenticator,
        store,
    };

    // build our application with some routes
    let app = Router::new()
        .route("/", get(handler::home))
        .route("/login", get(handler::login))
        .route("/callback", get(handler::callback))
        .route("/user", get(handler::user))
        .route("/logout", get(handler::logout))
        .with_state(app_state)
        .merge(SpaRouter::new("/public", "static"))
        .layer(TraceLayer::new_for_http())
        .layer(
            TraceLayer::new_for_http()
                .on_request(|_request: &Request<_>, _span: &Span| {
                    println!("{:?}", _request);
                    tracing::info!("{:?}", _request);
                })
                .on_response(|_response: &Response, _latency: Duration, _span: &Span| {
                    tracing::info!("{:?} {:?}", _response, _latency);
                })
                .on_body_chunk(|_chunk: &Bytes, _latency: Duration, _span: &Span| {
                    // ..
                })
                .on_eos(
                    |_trailers: Option<&HeaderMap>, _stream_duration: Duration, _span: &Span| {
                        // ...
                    },
                )
                .on_failure(
                    |_error: ServerErrorsFailureClass, _latency: Duration, _span: &Span| {
                        // ...
                    },
                ),
        );

    // run it
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

#[derive(Clone)]
struct AppState {
    authenticator: Authenticator,
    store: MemoryStore,
}

impl FromRef<AppState> for Authenticator {
    fn from_ref(state: &AppState) -> Self {
        state.authenticator.clone()
    }
}

impl FromRef<AppState> for MemoryStore {
    fn from_ref(state: &AppState) -> Self {
        state.store.clone()
    }
}

pub struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        Redirect::temporary("/").into_response()
    }
}
