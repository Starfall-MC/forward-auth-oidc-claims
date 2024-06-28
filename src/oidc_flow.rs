use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use axum::{extract::State, response::Redirect};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::{CookieJar, PrivateCookieJar};
use openidconnect::core::{CoreGenderClaim, CoreResponseType};
use openidconnect::reqwest::async_http_client;
use openidconnect::{AuthorizationCode, CsrfToken, Nonce, OAuth2TokenResponse, Scope};

use crate::additional_claims::AllOtherClaims;
use crate::AppState;

pub fn make_router() -> axum::Router<AppState> {
    Router::new()
        .route("/", get(|| async { "hello world" }))
        .route("/begin", get(begin_auth))
        .route("/authorize", get(authorize))
}

async fn begin_auth(
    State(app_state): State<AppState>,
    jar: PrivateCookieJar,
) -> (PrivateCookieJar, impl IntoResponse) {
    // Build the authorization URL
    let (auth_url, csrf_state, nonce) = app_state
        .client
        .authorize_url(
            openidconnect::AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("discord_id".to_string()))
        .url();

    let make_cookie = |name, value: &String| {
        Cookie::new(
            format!("{}{name}", app_state.cookie_prefix),
            value.to_owned(),
        )
    };

    let make_cookie_only_name = |name| Cookie::from(format!("{}{name}", app_state.cookie_prefix));

    // Save the CSRF and nonce into the cookie jar
    let jar = jar.remove(make_cookie_only_name("csrf"));
    let jar = jar.remove(make_cookie_only_name("nonce"));
    let jar = jar.add(make_cookie("csrf", csrf_state.secret()));
    let jar = jar.add(make_cookie("nonce", nonce.secret()));

    // Redirect the user to the authorization URL
    (jar, Redirect::to(auth_url.as_str()))
}

#[derive(serde::Deserialize)]
struct AuthState {
    code: AuthorizationCode,
    state: CsrfToken,
}

fn cookie_wipeout(state: AppState) -> CookieJar {
    let mut jar = CookieJar::new();
    // Set the csrf, nonce and token cookies to be deleted
    for name in ["csrf", "nonce", "token"] {
        jar = jar.add(
            Cookie::build(format!("{}{name}", state.cookie_prefix))
                .removal()
                .build(),
        );
    }
    jar
}

fn error_as_human(state: AppState, error: &str) -> impl IntoResponse {
    let mut text = format!("<html><body><h1>Sorry, an error occurred while logging you in.</h1>");
    text += &format!("<p>The error was: <code>{}</code>.</p>", error);

    text += "<p>You can try logging in again by proceeding to <a href=\"";
    text += state.app_url.as_str();
    text += "\">the app's index page</a>.</p>";
    text += "</body></html>";

    let mut headers = HeaderMap::new();

    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/html"),
    );

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        headers,
        cookie_wipeout(state),
        text,
    )
}

fn error_as_human_ctx<T: std::error::Error>(
    state: AppState,
    error: &str,
    internal: &T,
) -> impl IntoResponse {
    let mut text = format!("<html><body><h1>Sorry, an error occurred while logging you in.</h1>");
    text += &format!(
        "<p>The error was: <code>{}</code>; it was caused by:</p>",
        error
    );
    let mut err: Option<&dyn std::error::Error> = Some(internal);
    while let Some(cause) = err {
        text += &format!("<p><code>{} {:?}</code></p>", cause, cause);
        err = cause.source();
        if err.is_some() {
            text += "<p>... which was caused by...</p>";
        }
    }

    text += "<p>You can try logging in again by proceeding to <a href=\"";
    text += state.app_url.as_str();
    text += "\">the app's index page</a>.</p>";
    text += "</body></html>";

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/html"),
    );
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        headers,
        cookie_wipeout(state),
        text,
    )
}

async fn authorize(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Query(authz_state): Query<AuthState>,
) -> Response {
    let cookie_name = |name| format!("{}{name}", state.cookie_prefix);

    let csrf = jar.get(&cookie_name("csrf"));
    let nonce = jar.get(&cookie_name("nonce"));

    let (csrf, nonce) = match (csrf, nonce) {
        (Some(csrf), Some(nonce)) => (
            CsrfToken::new(csrf.value().to_string()),
            Nonce::new(nonce.value().to_string()),
        ),
        (None, _) => return error_as_human(state, "Missing CSRF token cookie").into_response(),
        (_, None) => return error_as_human(state, "Missing nonce cookie").into_response(),
    };

    if csrf.secret() != authz_state.state.secret() {
        return error_as_human(
            state,
            "CSRF token received from auth server did not match the one in the cookie",
        )
        .into_response();
    }

    // Now that we have the state, we can exchange it for an access token
    // async_http_client makes a new client for each request,
    // but that's okay as long as logins are rare.
    let token_response = state
        .client
        .exchange_code(authz_state.code)
        .request_async(async_http_client)
        .await;
    let token = match token_response {
        Ok(token) => token,
        Err(why) => {
            return error_as_human_ctx(
                state,
                "failed to contact auth server to perform token exchange",
                &why,
            )
            .into_response()
        }
    };

    let access_token = token.access_token();

    tracing::info!("Received access token: {:?}", token);

    let id_token = match token.extra_fields().id_token() {
        Some(id_token) => id_token,
        None => {
            return error_as_human(state, "auth server did not return an ID token").into_response()
        }
    };

    let id_token_verifier = state.client.id_token_verifier();
    let id_token_claims = id_token.claims(&id_token_verifier, &nonce);
    drop(id_token_verifier);

    let claims = match id_token_claims {
        Ok(claims) => claims,
        Err(why) => {
            return error_as_human_ctx(state, "failed to verify ID token", &why).into_response()
        }
    };

    tracing::info!("Received ID token: {:?}", claims);

    let user_info_request = state.client.user_info(access_token.clone(), None);
    let user_info_request = match user_info_request {
        Ok(user_info_request) => user_info_request,
        Err(why) => {
            return error_as_human_ctx(state, "failed to create user info request", &why)
                .into_response()
        }
    };
    let user_info_response = user_info_request.request_async(async_http_client).await;
    let user_info: openidconnect::UserInfoClaims<AllOtherClaims, CoreGenderClaim> =
        match user_info_response {
            Ok(user_info) => user_info,
            Err(why) => {
                return error_as_human_ctx(
                    state,
                    "failed to fetch user info from auth server",
                    &why,
                )
                .into_response()
            }
        };

    tracing::info!("Received user info: {:?}", user_info);

    error_as_human(state, "...").into_response()
}
