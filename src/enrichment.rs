use crate::{cookie::AuthTokenCookie, AppState};

pub async fn enrich_claims(
    token: &AuthTokenCookie,
    state: &AppState,
) -> reqwest::Result<AuthTokenCookie> {
    // If there is no enrichment URL, just return the token
    let url = if let Some(url) = &state.enrich_url {
        url
    } else {
        return Ok(token.clone());
    };

    let new_token = state
        .http_client
        .post(url)
        .json(token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    Ok(new_token)
}
