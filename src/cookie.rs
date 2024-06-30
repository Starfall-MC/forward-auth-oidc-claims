use openidconnect::{
    core::CoreGenderClaim, AccessToken, IdTokenClaims, Nonce, OAuth2TokenResponse, RefreshToken,
};
use serde::{Deserialize, Serialize};

use crate::additional_claims::{AllOtherClaims, MyTokenResponse};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthTokenCookie {
    pub acc: AccessToken,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refr: Option<RefreshToken>,

    #[serde(flatten)]
    pub claims: IdTokenClaims<AllOtherClaims, CoreGenderClaim>,
}

// TODO: I tried, but I can't use MessagePack, BSON, CBOR, because they have problems deserializing
// the structure of this
// But JSON cookies are huge, so we need to serialize them to a smaller size
// But using base65536 didn't work
// Figure out some better way than JSON+deflate?

impl AuthTokenCookie {
    pub fn to_cookie(&self) -> String {
        use base64::prelude::*;
        let raw = serde_json::to_string(&self).expect("failed to serialize token as JSON");
        let compressed = deflate::deflate_bytes(raw.as_bytes());
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

    #[cfg(test)]
    pub fn test_value() -> Self {
        use std::collections::HashMap;

        use openidconnect::{Audience, IssuerUrl, StandardClaims, SubjectIdentifier};

        AuthTokenCookie {
            acc: AccessToken::new("null".to_string()),
            refr: Default::default(),
            claims: IdTokenClaims::new(
                IssuerUrl::new("https://example.com".to_string()).unwrap(),
                vec![Audience::new("aud".to_string())],
                Default::default(),
                Default::default(),
                StandardClaims::new(SubjectIdentifier::new("sub".to_string())),
                AllOtherClaims(HashMap::new()),
            ),
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_auth_token_cookie_serde() {
        let token = super::AuthTokenCookie::test_value();
        let str = serde_json::to_string(&token).unwrap();
        println!("str: {}", str);

        let cookie = token.to_cookie();
        println!("cookie: {}", cookie);
        let _new_token = super::AuthTokenCookie::from_cookie(cookie).unwrap();
    }
}
