use thiserror::Error;

use crate::hardware;
use crate::licensing::splicense::{SPLicense, SPLicenseParseError};
use crate::licensing::utils::{generate_string, parse_bcrypt_rsa_private};
use crate::models::devicecredential::{Authentication, ClientInfo, DeviceAddRequest, DeviceInfo};
use crate::models::secrets::Device;
use crate::models::soap::BodyContent;
use crate::tokens::manager::TokenManager;
use crate::tokens::store::TokenStoreError;

#[derive(Debug, Error)]
pub enum DeviceCredentialError {
    #[error("could not provision a new device: {0}")]
    Provision(#[from] crate::api::live::LoginDeviceCredentialError),
    #[error("could not authenticate the device: {0}")]
    Authenticate(#[from] crate::api::live::rst::RSTError),
    #[error("could not parse the device's SPLicense: {0}")]
    LicenseParse(#[from] SPLicenseParseError),
    #[error("device SPLicense is missing its signing key")]
    MissingClepSignState,
    #[error("could not parse the device's RSA signing key: {0}")]
    RsaKey(#[from] rsa::errors::Error),
    #[error("device authentication response is missing key info")]
    MissingKeyInfo,
    #[error("failed to persist device credentials: {0}")]
    Storage(#[from] TokenStoreError),
}

/// Provisions a device (if none is stored yet) or re-authenticates an existing one
/// (if its STS token is missing/expired), persisting the result through `tokens`.
pub async fn ensure_device_credentials(
    client: &reqwest::Client,
    tokens: &TokenManager,
) -> Result<(), DeviceCredentialError> {
    match tokens.get_device_license() {
        Err(_) => provision_device(client, tokens).await,
        Ok(license) if tokens.get_device_sts_token().is_err() => {
            reauthenticate_device(client, tokens, license).await
        }
        Ok(_) => Ok(()),
    }
}

async fn provision_device(
    client: &reqwest::Client,
    tokens: &TokenManager,
) -> Result<(), DeviceCredentialError> {
    let username = format!("02{}", generate_string(14));
    let password = generate_string(20);
    let provision = DeviceAddRequest {
        client_info: ClientInfo::default(),
        authentication: Authentication::new(username.clone(), password.clone()),
        device_info: Some(DeviceInfo {
            id: "DeviceInfo".to_string(),
            components: hardware::probe_provision_components(),
            tpm_info: None,
        }),
    };

    let dev = crate::api::live::login_device_credential(client, provision).await?;

    let device = Device {
        username: username.clone(),
        password: password.clone(),
        puid: dev.puid,
        hwid: dev.hw_device_id,
        device_id: dev.license.binding.device_id.unwrap_or_default(),
        splicense: dev.license.splicense_block,
    };

    tokens.save_device_license(&device)?;

    reauthenticate_device(client, tokens, device).await
}

async fn reauthenticate_device(
    client: &reqwest::Client,
    tokens: &TokenManager,
    license: Device,
) -> Result<(), DeviceCredentialError> {
    let sp_license = SPLicense::parse_base64(&license.splicense)?;
    let clep_sign_state = sp_license
        .clep_sign_state
        .ok_or(DeviceCredentialError::MissingClepSignState)?;
    let key = clep_sign_state.get_rsa_key();
    let private_key = parse_bcrypt_rsa_private(&key)?;
    let resp = crate::api::live::authenticate_device(client, license.username, private_key).await?;

    if let BodyContent::RequestSecurityTokenResponse(resp) = resp.body.body {
        save_device_sts_token(tokens, resp)?;
    }
    Ok(())
}

fn save_device_sts_token(
    tokens: &TokenManager,
    resp: Box<crate::models::soap::RequestSecurityTokenResponse>,
) -> Result<(), DeviceCredentialError> {
    let key_name = resp
        .requested_security_token
        .encrypted_data
        .as_ref()
        .ok_or(DeviceCredentialError::MissingKeyInfo)?
        .key_info
        .key_name
        .as_ref()
        .ok_or(DeviceCredentialError::MissingKeyInfo)?
        .clone();
    let token = (*resp).into();
    tokens.save_device_token(key_name, token)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_device(splicense: &str) -> Device {
        Device {
            puid: "puid".to_string(),
            hwid: "hwid".to_string(),
            device_id: "device-id".to_string(),
            splicense: splicense.to_string(),
            username: "username".to_string(),
            password: "password".to_string(),
        }
    }

    #[tokio::test]
    async fn reauthenticate_reports_a_clean_error_on_an_unparseable_splicense() {
        let client = reqwest::Client::new();
        let tokens = TokenManager::with_memory();

        let err = reauthenticate_device(&client, &tokens, dummy_device("not valid base64!!"))
            .await
            .expect_err("garbage splicense should not parse");

        assert!(matches!(err, DeviceCredentialError::LicenseParse(_)));
    }
}
