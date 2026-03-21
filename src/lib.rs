mod models;

use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead};
use argon2::{Argon2};
use rand::RngCore;
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;
use crate::models::entry::Entry;
use crate::models::register_envelope::RegisterEnvelope;

#[wasm_bindgen]
pub fn generate_register_envelope(master_password: String) -> Result<RegisterEnvelope, JsValue> {
    if master_password.is_empty() {
        return Err(JsValue::NULL)
    }

    let master = master_password.as_bytes();
    let mut master_salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut master_salt);

    let mut k_master = [0u8; 32];
    Argon2::default().hash_password_into(master, &master_salt, &mut k_master)
        .map_err(|_| JsValue::NULL)?;

    let mut rng = rand::thread_rng();
    let kyber_keys = pqc_kyber::keypair(&mut rng)
        .map_err(|_| JsValue::NULL)?;

    let cipher = Aes256Gcm::new_from_slice(&k_master)
        .map_err(|_| JsValue::NULL)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let enc_sk = cipher.encrypt(&nonce, kyber_keys.secret.as_ref())
        .map_err(|_| JsValue::NULL)?;

    Ok(RegisterEnvelope::new(
        Vec::from(master_salt),
        enc_sk,
        Vec::from(kyber_keys.public),
        nonce.as_slice().into()
    ))
}

#[wasm_bindgen]
pub fn create_entry(password: String, pk: Vec<u8>) -> Result<Entry, JsValue> {
    if password.is_empty() {
        return Err(JsValue::NULL);
    }

    let password = password.as_bytes();

    let mut rng = rand::thread_rng();
    let (enc_kyber, cipher_key) = pqc_kyber::encapsulate(&pk, &mut rng)
        .map_err(|_| JsValue::NULL)?;

    let cipher = Aes256Gcm::new_from_slice(&cipher_key)
        .map_err(|_| JsValue::NULL)?;
    let pwd_nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let enc_pwd = cipher.encrypt(&pwd_nonce, password.as_ref())
        .map_err(|_| JsValue::NULL)?;

    Ok(Entry::new(
        enc_pwd,
        enc_kyber.to_vec(),
        pwd_nonce.as_slice().into()
    ))
}

#[wasm_bindgen]
pub fn read_entry(master_password: String, master_salt: Vec<u8>, enc_sk: Vec<u8>, sk_nonce: Vec<u8>, enc_pwd: Vec<u8>, enc_kyber: Vec<u8>, pwd_nonce: Vec<u8>) -> Result<String, JsValue> {
    let master_password = master_password.as_bytes();
    let master_salt = master_salt.as_slice();

    let mut k_master = [0u8; 32];
    Argon2::default().hash_password_into(master_password, master_salt, &mut k_master)
        .map_err(|_| JsValue::NULL)?;

    let cipher = Aes256Gcm::new_from_slice(&k_master)
        .map_err(|_| JsValue::NULL)?;
    let sk_nonce = Nonce::from_slice(sk_nonce.as_slice());
    let sk = cipher.decrypt(&sk_nonce, enc_sk.as_ref())
        .map_err(|_| JsValue::NULL)?;

    let cipher_key = pqc_kyber::decapsulate(&enc_kyber, &sk)
        .map_err(|_| JsValue::NULL)?;

    let cipher = Aes256Gcm::new_from_slice(&cipher_key)
        .map_err(|_| JsValue::NULL)?;
    let pwd_nonce = Nonce::from_slice(pwd_nonce.as_slice());
    let pwd = cipher.decrypt(&pwd_nonce, enc_pwd.as_ref())
        .map_err(|_| JsValue::NULL)?;

    Ok(String::from_utf8(pwd)
           .map_err(|_| JsValue::NULL)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_register_envelope_and_create_entry_and_read_entry() {
        let master_password = "SuperSecretPassword123!".to_string();

        // Génération de l'enveloppe d'enregistrement
        let envelope = generate_register_envelope(master_password.clone())
            .expect("Failed to create register envelope");

        // Création d'une entrée avec un mot de passe à stocker
        let password_to_store = "MyPassword42".to_string();
        let entry = create_entry(password_to_store.clone(), envelope.pk.clone())
            .expect("Failed to create entry");

        // Lecture du mot de passe à partir de l'entrée
        let result = read_entry(
            master_password.clone(),
            envelope.master_salt.clone(),
            envelope.enc_sk.clone(),
            envelope.sk_nonce.clone(),
            entry.enc_pwd.clone(),
            entry.enc_kyber.clone(),
            entry.pwd_nonce.clone(),
        ).expect("Failed to read entry");

        assert_eq!(result, password_to_store);
    }

    #[test]
    fn test_generate_register_envelope_invalid_password() {
        let envelope = generate_register_envelope(String::new());
        assert!(envelope.is_err());
    }

    #[test]
    fn test_create_entry_invalid_pk() {
        let result = create_entry("Password42!".to_string(), vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_entry_empty_password() {
        let result = create_entry(String::new(), vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_entry_invalid_data() {
        let result = read_entry(
            "test".to_string(),
            vec![0; 16],
            vec![0; 32],
            vec![0; 12],
            vec![0; 32],
            vec![0; 32],
            vec![0; 12],
        );
        assert!(result.is_err());
    }
}

