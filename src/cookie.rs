use openidconnect::{
    core::CoreGenderClaim, AccessToken, IdTokenClaims, Nonce, OAuth2TokenResponse, RefreshToken,
};
use serde::{Deserialize, Serialize};

use crate::additional_claims::{AllOtherClaims, MyTokenResponse};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthTokenCookie {
    pub acc: AccessToken,
    pub refr: Option<RefreshToken>,
    pub claims: IdTokenClaims<AllOtherClaims, CoreGenderClaim>,
}

impl AuthTokenCookie {
    pub fn to_cookie(&self) -> String {
        use base64::prelude::*;
        let raw = serde_json::to_string(&self).expect("failed to serialize token as JSON");
        let compressed = deflate::deflate_bytes(&raw.as_bytes());
        BASE64_URL_SAFE_NO_PAD.encode(&compressed)
    }

    pub fn from_cookie(data: String) -> Result<Self, String> {
        use base64::prelude::*;
        let compressed = BASE64_URL_SAFE_NO_PAD
            .decode(&data)
            .map_err(|e| e.to_string())?;
        let raw = inflate::inflate_bytes(&compressed).map_err(|e| e.to_string())?;
        serde_json::from_slice(&raw).map_err(|e| e.to_string())
    }

    pub fn from_token_response(
        token_response: &MyTokenResponse,
        state: &crate::AppState,
        nonce: &Nonce,
    ) -> Self {
        let access = token_response.access_token();
        let refresh = token_response.refresh_token();

        let claims = token_response
            .extra_fields()
            .id_token()
            .expect("server did not return an ID token")
            .claims(&state.client.id_token_verifier(), nonce)
            .expect("failed to verify ID token");
        Self {
            acc: access.clone(),
            refr: refresh.cloned(),
            claims: claims.clone(),
        }
    }
}
