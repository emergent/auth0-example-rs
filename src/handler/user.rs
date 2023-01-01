use super::HtmlTemplate;
use crate::extractor::Profile;
use askama::Template;
use axum::response::IntoResponse;
use tracing::instrument;

#[derive(Template)]
#[template(path = "user.html")]
struct UserTemplate {
    picture: String,
    nickname: String,
}

#[instrument]
pub async fn user(user: Profile) -> impl IntoResponse {
    let template = UserTemplate {
        picture: user.picture().unwrap_or_default(),
        nickname: user.nickname().unwrap_or_default(),
    };

    HtmlTemplate(template)
}
