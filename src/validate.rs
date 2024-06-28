use std::time::SystemTime;

use axum::http::Uri;
use axum::response::Redirect;
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue},
    response::IntoResponse,
};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::PrivateCookieJar;
use openidconnect::reqwest::async_http_client;
use openidconnect::Nonce;

use crate::cookie::AuthTokenCookie;
use crate::AppState;

/// Read the user's cookie
/// and check if the token is valid.
/// If it is, return the claims within it as headers
/// else return a redirect to the begin-auth path
pub async fn check_token(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    uri: Uri,
) -> impl IntoResponse {
    let mut headers = HeaderMap::new();

    let token = jar
        .get(&format!("{}token", state.cookie_prefix))
        .map(|cookie| cookie.value().to_owned());

    let nonce = jar
        .get(&format!("{}nonce", state.cookie_prefix))
        .map(|cookie| cookie.value().to_owned());

    if let Some(nonce) = nonce {
        let nonce = Nonce::new(nonce);
        if let Some(token) = token {
            match AuthTokenCookie::from_cookie(token) {
                Err(why) => {
                    headers.insert(
                        "X-Token-Error",
                        HeaderValue::from_str(why.as_str())
                            .unwrap_or(HeaderValue::from_static("non-ascii error")),
                    );
                }

                Ok(token) => {
                    tracing::info!("token validated: {:?}", token);

                    // If the token is not expired, return OK
                    // Otherwise, try refreshing it
                    let expiration: SystemTime = token.claims.expiration().into();
                    if expiration.elapsed().is_ok() {
                        // token is expired, refresh it
                        match try_refreshing_token(&state, &token, &nonce, &mut headers).await {
                            Some(token) => {
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

                                let jar = jar.add(make_cookie("token", &token.to_cookie()));
                                return (jar, headers, "OK").into_response();
                            }
                            None => {
                                // we failed to refresh the token,
                                // so we fall through to the redirect
                            }
                        }
                    } else {
                        return "OK".into_response();
                    }
                }
            }
        } else {
            headers.insert(
                "X-Token-Error",
                HeaderValue::from_static("Token value not found"),
            );
        }
    } else {
        headers.insert("X-Token-Error", HeaderValue::from_static("Nonce not found"));
    }

    // Return a redirect to the begin-auth path
    (
        headers,
        Redirect::to(&format!(
            "{}{}/begin?src_url={}",
            state.app_url,
            state.oidc_path,
            urlencoding::encode(&uri.to_string())
        )),
    )
        .into_response()
}

async fn try_refreshing_token(
    state: &AppState,
    token: &AuthTokenCookie,
    nonce: &Nonce,
    headers: &mut HeaderMap,
) -> Option<AuthTokenCookie> {
    // If we don't have a refresh token, nothing to do but redirect
    let refresh_token = match &token.refr {
        Some(refresh_token) => refresh_token,
        None => {
            headers.insert(
                "X-Token-Error",
                HeaderValue::from_static("Refresh token not granted, and access token expired"),
            );
            return None;
        }
    };

    // TODO: replace this with a global client
    match state
        .client
        .exchange_refresh_token(&refresh_token)
        .request_async(async_http_client)
        .await
    {
        Err(why) => {
            let mut headers = HeaderMap::new();
            headers.append(
                "X-Token-Error",
                HeaderValue::from_str(&why.to_string())
                    .unwrap_or(HeaderValue::from_static("non-ascii error")),
            );

            return None;
        }

        Ok(resp) => {
            headers.append(
                "X-Token-Status",
                HeaderValue::from_static("access token just refreshed"),
            );

            Some(AuthTokenCookie::from_token_response(&resp, state, nonce))
        }
    }
}
