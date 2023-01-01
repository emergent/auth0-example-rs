use super::HtmlTemplate;
use askama::Template;
use axum::response::IntoResponse;
use tracing::instrument;

#[derive(Template)]
#[template(path = "home.html")]
struct HomeTemplate;

#[instrument]
pub async fn home() -> impl IntoResponse {
    let template = HomeTemplate;
    HtmlTemplate(template)
}
