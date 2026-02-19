mod models;

use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead};
use argon2::{Argon2};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;
use crate::models::entry::Entry;
use crate::models::register_envelope::RegisterEnvelope;

#[wasm_bindgen]
pub fn generate_register_envelope(master_password: String, user_unique: String) -> Result<RegisterEnvelope, JsValue> {
    let master = master_password.as_bytes();
    let salt = user_unique.as_bytes();

    let mut k_master = [0u8; 32];
    Argon2::default().hash_password_into(master, salt, &mut k_master).map_err(|e| JsValue::from(e.to_string()))?;

    let mut rng = rand::thread_rng();
    let kyber_keys = pqc_kyber::keypair(&mut rng).map_err(|e| JsValue::from(e.to_string()))?;

    let cipher = Aes256Gcm::new_from_slice(&k_master).map_err(|e| JsValue::from(e.to_string()))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let enc_sk = cipher.encrypt(&nonce, kyber_keys.secret.as_ref()).map_err(|e| JsValue::from(e.to_string()))?;

    Ok(RegisterEnvelope::new(
        enc_sk,
        Vec::from(kyber_keys.public),
        nonce.as_slice().into()
    ))
}

#[wasm_bindgen]
pub fn create_entry(password: String, pk: Vec<u8>) -> Result<Entry, JsValue> {
    let password = password.as_bytes();

    let mut rng = rand::thread_rng();
    let (enc_kyber, cipher_key) = pqc_kyber::encapsulate(&pk, &mut rng).map_err(|e| JsValue::from(e.to_string()))?;

    let cipher = Aes256Gcm::new_from_slice(&cipher_key).map_err(|e| JsValue::from(e.to_string()))?;
    let pwd_nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let enc_pwd = cipher.encrypt(&pwd_nonce, password.as_ref()).map_err(|e| JsValue::from(e.to_string()))?;

    Ok(Entry::new(
        enc_pwd,
        enc_kyber.to_vec(),
        pwd_nonce.as_slice().into()
    ))
}

#[wasm_bindgen]
pub fn read_entry(master_password: String, user_unique: String, enc_sk: Vec<u8>, sk_nonce: Vec<u8>, enc_pwd: Vec<u8>, enc_kyber: Vec<u8>, pwd_nonce: Vec<u8>) -> Result<String, JsValue> {
    let master_password = master_password.as_bytes();
    let salt = user_unique.as_bytes();

    let mut k_master = [0u8; 32];
    Argon2::default().hash_password_into(master_password, salt, &mut k_master).map_err(|e| JsValue::from(e.to_string()))?;

    let cipher = Aes256Gcm::new_from_slice(&k_master).map_err(|e| JsValue::from(e.to_string()))?;
    let sk_nonce = Nonce::from_slice(sk_nonce.as_slice());
    let sk = cipher.decrypt(&sk_nonce, enc_sk.as_ref()).map_err(|e| JsValue::from(e.to_string()))?;

    let cipher_key = pqc_kyber::decapsulate(&enc_kyber, &sk).map_err(|e| JsValue::from(e.to_string()))?;

    let cipher = Aes256Gcm::new_from_slice(&cipher_key).map_err(|e| JsValue::from(e.to_string()))?;
    let pwd_nonce = Nonce::from_slice(pwd_nonce.as_slice());
    let pwd = cipher.decrypt(&pwd_nonce, enc_pwd.as_ref()).map_err(|e| JsValue::from(e.to_string()))?;

    Ok(String::from_utf8(pwd).map_err(|e| JsValue::from(e.to_string()))?)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_step() {

        // assert_eq!();
    }
}

