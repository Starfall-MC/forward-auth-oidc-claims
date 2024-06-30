use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::cookie::AuthTokenCookie;

pub fn drop_claims(token: AuthTokenCookie, which: &[String]) -> AuthTokenCookie {
    let critical_claims: HashSet<String> = {
        // These are the claims that we do not want to drop
        // Most are from the requirements of serde
        // "refr" is our refresh token, which should be preserved
        let items = ["sub", "acc", "iss", "exp", "iat", "refr"];

        HashSet::from_iter(items.iter().map(|v| v.to_string()))
    };

    // We are transforming this to the hashmap representation,
    // then serializing back to a JSON string
    // and then parsing it back into the AuthTokenCookie
    // This is inefficient, but it should be fine because this only happens on token issuance and renewal,
    // rather than on every request.

    let src_token_str = serde_json::to_string(&token).expect("failure in serializing token");

    let mut src_token_map: HashMap<String, Value> =
        serde_json::from_str(&src_token_str).expect("failure in deserializing token");

    for claim in which {
        if !critical_claims.contains(claim) {
            src_token_map.remove(claim);
        } else {
            tracing::warn!("claim {} is critical and will not be dropped", claim);
        }
    }

    let new_token_str =
        serde_json::to_string(&src_token_map).expect("failure in serializing token");
    let new_token = serde_json::from_str(&new_token_str).expect("failure in deserializing token");
    new_token
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use openidconnect::{
        AccessToken, Audience, IdTokenClaims, IssuerUrl, StandardClaims, SubjectIdentifier,
    };

    use crate::additional_claims::AllOtherClaims;

    use super::*;

    #[test]
    fn test_drop_claims() {
        let token = AuthTokenCookie {
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
        };

        // Gather all keys
        let token_json = serde_json::to_string(&token).unwrap();
        let token_map: HashMap<String, Value> = serde_json::from_str(&token_json).unwrap();
        let keys = token_map.keys().cloned().collect::<Vec<String>>();

        // Should have no problems serializing, even when requesting that all keys are dropped
        let _new_token = drop_claims(token, &keys);
    }
}
