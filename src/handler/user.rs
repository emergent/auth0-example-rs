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
        picture: user
            .profile()
            .as_ref()
            .picture()
            .unwrap()
            .get(None)
            .unwrap()
            .to_string(),
        nickname: user
            .profile()
            .as_ref()
            .nickname()
            .unwrap()
            .get(None)
            .unwrap()
            .to_string(),
    };

    HtmlTemplate(template)
}
