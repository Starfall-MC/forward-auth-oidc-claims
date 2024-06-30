use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{extract::State, response::Redirect};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::{CookieJar, PrivateCookieJar};
use openidconnect::core::CoreResponseType;
use openidconnect::{AuthorizationCode, CsrfToken, Nonce, Scope};

use crate::cookie::AuthTokenCookie;
use crate::enrichment::enrich_claims;
use crate::AppState;

// pub fn make_router() -> axum::Router<AppState> {
//     Router::new()
//         .route("/", get(|| async { "hello world" }))
//         .route("/begin", get(begin_auth))
//         .route("/authorize", get(authorize))
// }

#[derive(serde::Deserialize)]
struct BeginAuthQuery {
    #[serde(default = "default_src_url")]
    pub src_url: String,
}

fn default_src_url() -> String {
    "/".to_string()
}

#[derive(serde::Deserialize, Debug)]
pub struct AuthorizeQuery {
    pub src_url: Option<String>,
    pub code: Option<AuthorizationCode>,
    pub state: Option<CsrfToken>,
    pub error: Option<String>,
}

pub async fn dispatch(
    State(app_state): State<AppState>,
    jar: PrivateCookieJar,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    tracing::debug!(
        "Dispatching into oidc_flow::dispatch with query: {:?}",
        query
    );
    // If the code and state are provided, this is an authorize request
    if let (Some(code), Some(state)) = (query.code, query.state) {
        tracing::debug!("Code and state provided; dispatching into authorize");
        return authorize(State(app_state), jar, Query(AuthState { code, state })).await;
    }

    // If there is an error, we need to show the error message
    if let Some(error) = query.error {
        return error_as_human(
            app_state,
            &format!("Received OIDC error callback with error value: {error}"),
        )
        .into_response();
    }

    // Otherwise, this is a begin request
    tracing::debug!(
        "Code and state not provided, only url: {:?}; dispatching into begin_auth",
        query.src_url
    );
    begin_auth(
        State(app_state),
        jar,
        Query(BeginAuthQuery {
            src_url: query.src_url.unwrap_or_else(default_src_url),
        }),
    )
    .await
    .into_response()
}

async fn begin_auth(
    State(app_state): State<AppState>,
    jar: PrivateCookieJar,
    Query(BeginAuthQuery { src_url }): Query<BeginAuthQuery>,
) -> (PrivateCookieJar, impl IntoResponse) {
    // Build the authorization URL
    let mut query = app_state.client.authorize_url(
        openidconnect::AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
    );

    for scope in app_state.scopes.iter() {
        query = query.add_scope(Scope::new(scope.to_string()));
    }

    let (auth_url, csrf_state, nonce) = query.url();

    let cookie_path = app_state.cookie_path.clone();
    let make_cookie = |name, value: &String| {
        Cookie::build(Cookie::new(
            format!("{}{name}", app_state.cookie_prefix),
            value.to_owned(),
        ))
        .path(cookie_path.clone())
        .build()
    };

    let make_cookie_only_name = |name| Cookie::from(format!("{}{name}", app_state.cookie_prefix));

    // Save the CSRF and nonce into the cookie jar
    let jar = jar.remove(make_cookie_only_name("csrf"));
    let jar = jar.remove(make_cookie_only_name("nonce"));
    let jar = jar.remove(make_cookie_only_name("src_url"));
    let jar = jar.add(make_cookie("csrf", csrf_state.secret()));
    let jar = jar.add(make_cookie("nonce", nonce.secret()));
    let jar = jar.add(make_cookie("src_url", &src_url));

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
    // Set the used cookies to be deleted
    for name in ["csrf", "nonce", "token", "src_url"] {
        jar = jar.add(
            Cookie::build(format!("{}{name}", state.cookie_prefix))
                .removal()
                .build(),
        );
    }
    jar
}

fn error_as_human(state: AppState, error: &str) -> impl IntoResponse {
    let mut text =
        "<html><body><h1>Sorry, an error occurred while logging you in.</h1>".to_string();
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
    let mut text =
        "<html><body><h1>Sorry, an error occurred while logging you in.</h1>".to_string();
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

    let src_url = jar
        .get(&cookie_name("src_url"))
        .unwrap_or_else(|| Cookie::new("src_url", "/"));

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
        .request_async(|v| state.async_http_client(v))
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

    // let access_token = token.access_token();

    // tracing::info!("Received access token: {:?}", token);

    // let id_token = match token.extra_fields().id_token() {
    //     Some(id_token) => id_token,
    //     None => {
    //         return error_as_human(state, "auth server did not return an ID token").into_response()
    //     }
    // };

    // let id_token_verifier = state.client.id_token_verifier();
    // let id_token_claims = id_token.claims(&id_token_verifier, &nonce);
    // drop(id_token_verifier);

    // let claims = match id_token_claims {
    //     Ok(claims) => claims,
    //     Err(why) => {
    //         return error_as_human_ctx(state, "failed to verify ID token", &why).into_response()
    //     }
    // };

    // tracing::info!("Received ID token: {:?}", claims);

    // let user_info_request = state.client.user_info(access_token.clone(), None);
    // let user_info_request = match user_info_request {
    //     Ok(user_info_request) => user_info_request,
    //     Err(why) => {
    //         return error_as_human_ctx(state, "failed to create user info request", &why)
    //             .into_response()
    //     }
    // };
    // let user_info_response = user_info_request
    //     .request_async(|v| state.async_http_client(v))
    //     .await;
    // let user_info: openidconnect::UserInfoClaims<AllOtherClaims, CoreGenderClaim> =
    //     match user_info_response {
    //         Ok(user_info) => user_info,
    //         Err(why) => {
    //             return error_as_human_ctx(
    //                 state,
    //                 "failed to fetch user info from auth server",
    //                 &why,
    //             )
    //             .into_response()
    //         }
    //     };

    // tracing::info!("Received user info: {:?}", user_info);

    // Now we have a valid access token.
    // Save that into a cookie,
    // then redirect back to the original URL.

    let cookie_prefix = state.cookie_prefix.clone();
    let cookie_path = state.cookie_path.clone();
    let make_cookie = |name, value: &String| {
        Cookie::build(Cookie::new(
            format!("{}{name}", cookie_prefix),
            value.to_owned(),
        ))
        .path(cookie_path)
        .build()
    };

    let packed_token = AuthTokenCookie::from_token_response(&token, &state, &nonce);

    #[cfg(feature = "enrichment")]
    let packed_token = {
        match enrich_claims(&packed_token, &state).await {
            Ok(v) => v,
            Err(why) => {
                return error_as_human_ctx(
                    state,
                    "After a successful OIDC flow, failed to enrich returned claims. This is an internal server error.",
                    &why,
                )
                .into_response()
            }
        }
    };

    let make_cookie_only_name = |name| Cookie::from(format!("{}{name}", state.cookie_prefix));

    let jar = jar.remove(make_cookie_only_name("csrf"));
    // let jar = jar.remove(make_cookie_only_name("nonce"));
    let jar = jar.remove(make_cookie_only_name("src_url"));
    let jar = jar.add(make_cookie("token", &packed_token.to_cookie()));

    tracing::debug!("OIDC flow completed successfully, redir to {:?}", src_url);
    // We have ensured that the cookie only contains the path-and-query.
    // Return a redirect to the original domain
    (
        jar,
        Redirect::to(&format!("{}{}", state.app_url, src_url.value())),
    )
        .into_response()
}
