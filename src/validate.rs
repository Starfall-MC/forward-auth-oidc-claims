use axum::http::StatusCode;
use axum::response::Redirect;
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue},
    response::IntoResponse,
};
use axum_extra::extract::CookieJar;

use crate::AppState;

/// Read the user's cookie
/// and check if the token is valid.
/// If it is, return the claims within it as headers
/// else return a redirect to the begin-auth path
pub async fn check_token(State(app_state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    let mut headers = HeaderMap::new();

    let token = jar.get("token").map(|cookie| cookie.value().to_owned());

    if let Some(token) = token {
        // TODO: check token
        tracing::info!("Received token: {token:?}");
        headers.insert("x-validity", HeaderValue::from_str("idfk").unwrap());

        return (StatusCode::OK, headers, "todo: ok").into_response();
    }

    // Return a redirect to the begin-auth path
    Redirect::to(&format!(
        "{}{}/begin",
        app_state.app_url, app_state.oidc_path
    ))
    .into_response()
}
