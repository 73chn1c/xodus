use std::cmp::min;
use std::collections::HashMap;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, KeyIvInit};
use base64::prelude::*;
use hmac::{Hmac, KeyInit, Mac};
use rsa::rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zerocopy::IntoBytes;

use crate::api::live::rst;
use crate::models::soap;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// SP800_108 HMAC with counter
/// - key_usage - KDF_LABEL
/// - context - KDF_CONTEXT
pub fn generate_shared_key(
    key_length: usize,
    in_key: &[u8],
    key_usage: &str,
    context: &[u8],
) -> [u8; 32] {
    let len: usize = 4 + key_usage.len() + 1 + context.len() + 4;
    let mut shared_key_material: Vec<u8> = vec![0; len];

    let mut offset = 0;
    offset += 4;
    shared_key_material[offset..offset + key_usage.len()].copy_from_slice(key_usage.as_bytes());
    offset += key_usage.len();

    // Already zerod
    offset += 1;

    shared_key_material[offset..offset + context.len()].copy_from_slice(context);
    offset += context.len();

    let key_bit_length = u32::try_from(key_length * 8).unwrap();
    shared_key_material[offset..offset + 4].copy_from_slice(&key_bit_length.to_be_bytes());

    offset += 4;

    let mut current_key_length: usize = 0;
    let mut current_hash_count: u32 = 1;

    let mut shared_key = [0; 32];

    while current_key_length < key_length {
        shared_key_material[0..4].copy_from_slice(&current_hash_count.to_be_bytes());

        current_hash_count += 1;

        type HmacSha256 = Hmac<Sha256>;

        let mut hmac = HmacSha256::new_from_slice(in_key).unwrap();
        hmac.update(&shared_key_material[..offset]);
        let signature = hmac.finalize().into_bytes();
        let amount = min(signature.len(), key_length - current_key_length);
        shared_key[current_key_length..current_key_length + amount]
            .copy_from_slice(&signature.as_bytes()[0..amount]);
        current_key_length += amount;
    }

    shared_key
}

pub fn generate_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    _ = OsRng.try_fill_bytes(&mut nonce);
    nonce
}

pub fn sign_xml(
    signature: Option<&super::rst::RSTSignature>,
    nonce: &[u8],
    xml_text: String,
) -> Result<String, rst::RSTBuilderError> {
    let Some(signature) = signature else {
        return Ok(xml_text);
    };
    let min_xml = bergshamra::c14n::canonicalize(
        &xml_text,
        bergshamra_c14n::C14nMode::Exclusive,
        None,
        &[] as &[&str],
    )?;

    let mut kmgr = bergshamra::KeysManager::new();
    let key = signature.signing_key(nonce)?;

    kmgr.add_key(bergshamra::Key::new(key, bergshamra::KeyUsage::Sign));
    let ctx = bergshamra::DsigContext::new(kmgr).with_strict_verification(false);
    let signed = bergshamra::sign(&ctx, std::str::from_utf8(&min_xml).unwrap())?;
    Ok(signed)
}

pub fn decrypt_soap_encrypted_data<T: serde::de::DeserializeOwned>(
    encrypted_data: Box<soap::EncryptedData>,
    signature: &rst::RSTSignature,
    nonces: &HashMap<String, String>,
) -> Result<T, rst::RSTError> {
    let id = &encrypted_data
        .key_info
        .as_signature()
        .security_token_reference
        .reference
        .uri;

    let nonce = nonces.get(&id[1..]).ok_or(rst::RSTError::MissingNonce)?;
    let nonce = BASE64_STANDARD.decode(nonce)?;
    let key = signature.hmac_key(&nonce).ok_or(rst::RSTError::HmacKey)?;
    let cipher_value = BASE64_STANDARD.decode(encrypted_data.cipher_data.cipher_value)?;

    if cipher_value.len() < 16 {
        return Err(rst::RSTError::InvalidEncryptedData(format!(
            "cipher_value is {} bytes, shorter than the 16-byte IV",
            cipher_value.len()
        )));
    }
    let (iv, encrypted) = cipher_value.split_at(16);
    let iv: &[u8; 16] = iv.try_into().unwrap();
    let decryptor = Aes256CbcDec::new(&key.into(), iv.into());
    // Ciphertext length is always >= plaintext length for CBC+PKCS7, so this
    // is a safe upper bound regardless of payload size (no fixed 8192B cap).
    let mut block = vec![0u8; encrypted.len()];

    let plaintext = decryptor
        .decrypt_padded_b2b::<Pkcs7>(encrypted, &mut block)
        .map_err(|_| rst::RSTError::InvalidEncryptedData("PKCS7 unpadding failed".to_string()))?;
    let result = std::str::from_utf8(plaintext).map_err(|_| {
        rst::RSTError::InvalidEncryptedData("decrypted payload is not valid UTF-8".to_string())
    })?;
    let data = quick_xml::de::from_str::<T>(result)?;

    Ok(data)
}

#[cfg(test)]
mod real_fn_tests {
    use std::collections::HashMap;

    use aes::cipher::block_padding::Pkcs7;
    use aes::cipher::{BlockModeEncrypt, KeyIvInit};
    use base64::prelude::*;

    use super::decrypt_soap_encrypted_data;
    use crate::api::live::rst::RSTSignature;
    use crate::models::soap;

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    const NONCE: [u8; 32] = [3u8; 32];
    const CLEP_SECRET: [u8; 32] = [11u8; 32];

    /// Builds exactly what the production function expects: an EncryptedData
    /// whose KeyInfo points at "#SignKey", plus a nonce map keyed "SignKey".
    fn encrypted_data_for(plaintext: &str) -> Box<soap::EncryptedData> {
        let sig = RSTSignature::Hmac {
            clep_secret: &CLEP_SECRET,
            tpm_secret: &[],
        };
        let key = sig.hmac_key(&NONCE).expect("hmac key");
        let iv = [5u8; 16];

        let mut buf = vec![0u8; plaintext.len() + 32];
        let ct = Aes256CbcEnc::new(&key.into(), &iv.into())
            .encrypt_padded_b2b::<Pkcs7>(plaintext.as_bytes(), &mut buf)
            .expect("encrypt");

        let mut body = iv.to_vec();
        body.extend_from_slice(ct);

        Box::new(soap::EncryptedData {
            id: "BinaryDAToken0".to_string(),
            xmlns: "http://www.w3.org/2001/04/xmlenc#".to_string(),
            el_type: "http://www.w3.org/2001/04/xmlenc#Element".to_string(),
            encryption_method: soap::EncryptionMethod::default(),
            key_info: soap::KeyInfoWrap {
                ds: None,
                key_name: None,
                security_token_reference: Some(soap::SecurityTokenReference {
                    reference: soap::ReferenceUri {
                        uri: "#SignKey".to_string(),
                    },
                }),
            },
            cipher_data: soap::CipherData::new(BASE64_STANDARD.encode(&body)),
        })
    }

    fn nonces() -> HashMap<String, String> {
        HashMap::from([("SignKey".to_string(), BASE64_STANDARD.encode(NONCE))])
    }

    fn sig() -> RSTSignature<'static> {
        RSTSignature::Hmac {
            clep_secret: &CLEP_SECRET,
            tpm_secret: &[],
        }
    }

    /// Control: proves the harness itself is correct, so a panic in the other
    /// tests is the production code and not my test setup.
    #[test]
    fn control_small_payload_round_trips() {
        let data = encrypted_data_for("<Root><Token>abc</Token></Root>");
        let out: serde_json::Value =
            decrypt_soap_encrypted_data(data, &sig(), &nonces()).expect("should decrypt");
        println!("CONTROL ok -> {out:?}");
    }

    /// Previously panicked at the fixed 8192-byte buffer; now the buffer is
    /// sized to the ciphertext, so a >8KiB token round-trips cleanly.
    #[test]
    fn payload_larger_than_the_old_8192_cap_round_trips() {
        let pt = format!("<Root><Token>{}</Token></Root>", "A".repeat(9000));
        let data = encrypted_data_for(&pt);
        let _: serde_json::Value = decrypt_soap_encrypted_data(data, &sig(), &nonces())
            .expect("large payload must decrypt cleanly, not panic");
    }

    /// Previously panicked in `cipher_value.split_at(16)`; now returns a
    /// clean `RSTError::InvalidEncryptedData`.
    #[test]
    fn cipher_value_shorter_than_the_iv_returns_clean_error() {
        let mut data = encrypted_data_for("<Root/>");
        data.cipher_data.cipher_value = BASE64_STANDARD.encode([1u8, 2, 3]);
        let err = decrypt_soap_encrypted_data::<serde_json::Value>(data, &sig(), &nonces())
            .expect_err("short cipher_value must be a clean error, not a panic");
        assert!(matches!(
            err,
            crate::api::live::rst::RSTError::InvalidEncryptedData(_)
        ));
    }
}
