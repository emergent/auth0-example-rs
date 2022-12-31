use askama::Template;
use async_lock::RwLock;
use async_session::{MemoryStore, Session, SessionStore};
use axum::{
    async_trait,
    extract::{
        rejection::TypedHeaderRejectionReason, FromRef, FromRequestParts, Query, State, TypedHeader,
    },
    http::{header, header::SET_COOKIE, request::Parts, HeaderMap, Request, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    RequestPartsExt, Router,
};
use axum_extra::routing::SpaRouter;
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreIdTokenClaims, CoreProviderMetadata},
    reqwest::async_http_client,
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, RedirectUrl, Scope,
};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::Deserialize;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tower_http::trace::TraceLayer;
use tracing::{instrument, Span};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

static COOKIE_NAME: &str = "auth-session";

#[derive(Deserialize, Clone, Debug)]
struct Auth0Env {
    client_id: String,
    domain: String,
    client_secret: String,
    audience: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "auth0_example_rs=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    dotenv::dotenv().ok();
    let auth0_env = envy::prefixed("AUTH0_")
        .from_env::<Auth0Env>()
        .expect("env error");

    // `MemoryStore` is just used as an example. Don't use this in production.
    let store = MemoryStore::new();
    let oidc_client = oidc_client(&auth0_env).await?;
    let oidc_store = Arc::new(RwLock::new(HashMap::new()));
    let app_state = AppState {
        store,
        oidc_client,
        oidc_store,
        auth0_env,
    };

    // build our application with some routes
    let app = Router::new()
        .route("/", get(home))
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/user", get(user))
        .route("/logout", get(logout))
        .with_state(app_state)
        .merge(SpaRouter::new("/public", "static"))
        .layer(TraceLayer::new_for_http())
        .layer(
            TraceLayer::new_for_http()
                .on_request(|_request: &Request<_>, _span: &Span| {
                    tracing::info!("{:?}", _request);
                })
                .on_response(|_response: &Response, _latency: Duration, _span: &Span| {
                    tracing::info!("{:?} {:?}", _response, _latency);
                }),
        );

    // run it
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

type OidcStore = Arc<RwLock<HashMap<String, Nonce>>>;

#[derive(Clone)]
struct AppState {
    store: MemoryStore,
    oidc_client: CoreClient,
    oidc_store: OidcStore,
    auth0_env: Auth0Env,
}

impl FromRef<AppState> for MemoryStore {
    fn from_ref(state: &AppState) -> Self {
        state.store.clone()
    }
}

impl FromRef<AppState> for CoreClient {
    fn from_ref(state: &AppState) -> Self {
        state.oidc_client.clone()
    }
}

impl FromRef<AppState> for OidcStore {
    fn from_ref(state: &AppState) -> Self {
        state.oidc_store.clone()
    }
}

impl FromRef<AppState> for Auth0Env {
    fn from_ref(state: &AppState) -> Self {
        state.auth0_env.clone()
    }
}

async fn oidc_client(auth0env: &Auth0Env) -> anyhow::Result<CoreClient> {
    let auth_url = format!("https://{}/", auth0env.domain);

    let provider_metadata =
        CoreProviderMetadata::discover_async(IssuerUrl::new(auth_url)?, async_http_client).await?;

    dbg!(&provider_metadata);

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(auth0env.client_id.clone()),
        Some(ClientSecret::new(auth0env.client_secret.clone())),
    )
    .set_redirect_uri(RedirectUrl::new(format!("{}/callback", auth0env.audience))?);

    Ok(client)
}

#[derive(Template)]
#[template(path = "home.html")]
struct HomeTemplate;

#[instrument]
async fn home() -> impl IntoResponse {
    let template = HomeTemplate;
    HtmlTemplate(template)
}

#[instrument]
async fn login(
    State(store): State<OidcStore>,
    State(client): State<CoreClient>,
) -> impl IntoResponse {
    // Generate the full authorization URL.
    let (auth_url, csrf_token, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        // Set the desired scopes.
        .add_scope(Scope::new("profile".to_string()))
        .url();

    store
        .write()
        .await
        .insert(csrf_token.secret().to_owned(), nonce);

    tracing::debug!("{:?}", &store);

    Redirect::to(auth_url.as_ref())
}

#[instrument]
async fn logout(
    //user: User,
    State(store): State<MemoryStore>,
    State(auth0_env): State<Auth0Env>,
) -> impl IntoResponse {
    let logout_url = format!(
        "https://{}/v2/logout?returnTo={}&client_id={}",
        auth0_env.domain,
        utf8_percent_encode(&auth0_env.audience, NON_ALPHANUMERIC),
        utf8_percent_encode(&auth0_env.client_id, NON_ALPHANUMERIC),
    );

    tracing::debug!("{:?}", &store);

    Redirect::to(&logout_url)
}

struct HtmlTemplate<T>(T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template. Error: {}", err),
            )
                .into_response(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AuthRequest {
    code: String,
    state: String,
}

#[instrument]
async fn callback(
    Query(query): Query<AuthRequest>,
    State(store): State<MemoryStore>,
    State(oidc_client): State<CoreClient>,
    State(oidc_store): State<OidcStore>,
) -> impl IntoResponse {
    let state = query.state;
    let nonce = oidc_store.read().await.get(&state).cloned().unwrap();

    tracing::debug!("{:?}", &oidc_store);
    tracing::debug!("{:?}", state);

    // Get an auth token
    let token_response = oidc_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await
        .unwrap();

    let id_token_verifier = oidc_client.id_token_verifier();
    let id_token = token_response.extra_fields().id_token().unwrap();
    let id_token_claims = id_token.claims(&id_token_verifier, &nonce).unwrap();

    if let Some(expected_access_token_hash) = id_token_claims.access_token_hash() {
        let actual = AccessTokenHash::from_token(
            token_response.access_token(),
            &id_token.signing_alg().unwrap(),
        )
        .unwrap();

        if actual != *expected_access_token_hash {
            panic!();
        }
    }

    // Create a new session filled with user data
    let mut session = Session::new();
    session
        .insert("access_token", token_response.access_token().secret())
        .unwrap();
    session.insert("profile", id_token_claims.clone()).unwrap();

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

struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        Redirect::temporary("/").into_response()
    }
}

#[derive(Template)]
#[template(path = "user.html")]
struct UserTemplate {
    picture: String,
    nickname: String,
}

#[instrument]
async fn user(user: User) -> impl IntoResponse {
    let template = UserTemplate {
        picture: user
            .profile
            .picture()
            .unwrap()
            .get(None)
            .unwrap()
            .to_string(),
        nickname: user
            .profile
            .nickname()
            .unwrap()
            .get(None)
            .unwrap()
            .to_string(),
    };

    HtmlTemplate(template)
}

#[derive(Debug, Clone)]
struct User {
    profile: CoreIdTokenClaims,
}

#[async_trait]
impl<S> FromRequestParts<S> for User
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

        let profile = session
            .get::<CoreIdTokenClaims>("profile")
            .ok_or(AuthRedirect)?;

        Ok(User { profile })
    }
}
