use crate::models::live::ExchangeUserTokenOutcome;
use crate::models::secrets::{LegacyToken, Token};
use crate::models::soap;
use crate::models::xbox::XstsResponse;

pub mod auth;
pub mod title;
pub use auth::{authenticate_xbox_user, get_xsts_auth_header, request_xsts_token};

#[derive(thiserror::Error, Debug)]
pub enum XboxAuthError {
    #[error("Failed to exchange MS user token: {0}")]
    ExchangeUserToken(String),
    #[error("MS user token exchange returned a fault")]
    TokenExchangeFault,
    #[error("Expected RequestSecurityTokenResponse but token collection was empty")]
    EmptyTokenCollection,
    #[error("Unsupported token type, expected Compact token")]
    UnsupportedTokenType,
    #[error("Failed to authenticate Xbox user: {0}")]
    XboxUserAuth(#[from] reqwest::Error),
    #[error("Failed to obtain XSTS token: {0}")]
    XstsRequest(String),
}

pub async fn run(
    client: &reqwest::Client,
    dev_token: LegacyToken,
    legacy: LegacyToken,
    relying_party: &str,
) -> Result<XstsResponse, XboxAuthError> {
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
    .map_err(|e| XboxAuthError::ExchangeUserToken(e.to_string()))?;

    let user_token: Token = match user_token {
        ExchangeUserTokenOutcome::Fault(_) => {
            return Err(XboxAuthError::TokenExchangeFault);
        }
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
        ) => {
            if collection.security_tokens.is_empty() {
                return Err(XboxAuthError::EmptyTokenCollection);
            }
            let token = collection.security_tokens.remove(0);
            token.into()
        }
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
            token,
        )) => (*token).into(),
        _ => return Err(XboxAuthError::UnsupportedTokenType),
    };
    let Token::Compact(user_token) = user_token else {
        return Err(XboxAuthError::UnsupportedTokenType);
    };
    let resp = authenticate_xbox_user(client, user_token)
        .await
        .map_err(XboxAuthError::XboxUserAuth)?;

    request_xsts_token(client, resp.token, relying_party)
        .await
        .map_err(|e| XboxAuthError::XstsRequest(e.to_string()))
}
