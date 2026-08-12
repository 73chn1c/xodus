use crate::models::live::ExchangeUserTokenOutcome;
use crate::models::secrets::{LegacyToken, Token};
use crate::models::soap;
use crate::models::xbox::XstsResponse;
use crate::tokens::TokenManager;

pub mod auth;
pub mod title;
pub use auth::{authenticate_xbox_user, get_xsts_auth_header, request_xsts_token};

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    dev_token: LegacyToken,
    legacy: LegacyToken,
    relying_party: &str,
) -> XstsResponse {
    if let Some(cached) = tokens.get_cached_xsts(relying_party) {
        return cached;
    }

    let user_token = crate::api::live::exchange_user_token(
        client,
        legacy,
        "USERNAME".to_string(),
        dev_token,
        None,
        Some("Silent".to_string()),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        &[(
            "user.auth.xboxlive.com".to_owned(),
            Some(soap::PolicyReference::mbi_ssl()),
        )],
    )
    .await
    .expect("Failed to get ms user token");

    let user_token: Token = match user_token {
        ExchangeUserTokenOutcome::Fault(_) => {
            eprintln!("Failed to get exchange MS token");
            panic!("TODO");
        }
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
        ) => {
            let token = collection.security_tokens.remove(0);
            token.into()
        }
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
            token,
        )) => (*token).into(),
        _ => unreachable!("Only responses are handled"),
    };
    let Token::Compact(user_token) = user_token else {
        eprintln!("Unsupported token");
        panic!("TODO");
    };
    let resp = authenticate_xbox_user(client, user_token)
        .await
        .expect("Failed to authenticate Xbox user");

    let xsts = request_xsts_token(client, resp.token, relying_party)
        .await
        .expect("Failed to authenticate Xbox user");

    tokens.cache_xsts(relying_party, &xsts);
    xsts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::soap::Timestamp;

    fn dummy_legacy_token() -> LegacyToken {
        LegacyToken {
            key_name: None,
            token: "dummy".to_string(),
            binary_secret: None,
            tpm_key: None,
            lifetime: Timestamp {
                id: None,
                created: "2020-01-01T00:00:00Z".to_string(),
                expires: "2099-01-01T00:00:00Z".to_string(),
            },
        }
    }

    fn dummy_xsts(token: &str) -> XstsResponse {
        serde_json::from_str(&format!(
            r#"{{"NotAfter":"2099-01-01T00:00:00Z","Token":"{token}","DisplayClaims":{{"xui":[{{"uhs":"dummy-hash"}}]}}}}"#
        ))
        .expect("valid dummy XstsResponse json")
    }

    #[tokio::test]
    async fn run_returns_the_cached_token_without_hitting_the_network() {
        let tokens = TokenManager::with_memory();
        let relying_party = "http://update.xboxlive.com";
        tokens.cache_xsts(relying_party, &dummy_xsts("cached-token"));

        let client = reqwest::Client::new();
        let result = run(
            &client,
            &tokens,
            dummy_legacy_token(),
            dummy_legacy_token(),
            relying_party,
        )
        .await;

        assert_eq!(result.token, "cached-token");
    }

    #[test]
    fn cache_is_keyed_per_relying_party() {
        let tokens = TokenManager::with_memory();
        tokens.cache_xsts("http://update.xboxlive.com", &dummy_xsts("a"));

        assert!(
            tokens
                .get_cached_xsts("http://licensing.xboxlive.com")
                .is_none()
        );
        assert_eq!(
            tokens
                .get_cached_xsts("http://update.xboxlive.com")
                .unwrap()
                .token,
            "a"
        );
    }

    #[test]
    fn expired_cache_entries_are_not_returned() {
        let tokens = TokenManager::with_memory();
        let relying_party = "http://update.xboxlive.com";
        let already_expired: XstsResponse = serde_json::from_str(
            r#"{"NotAfter":"2000-01-01T00:00:00Z","Token":"stale","DisplayClaims":{"xui":[{"uhs":"h"}]}}"#,
        )
        .unwrap();
        tokens.cache_xsts(relying_party, &already_expired);

        assert!(tokens.get_cached_xsts(relying_party).is_none());
    }
}
