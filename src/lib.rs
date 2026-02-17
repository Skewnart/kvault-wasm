mod models;

use aes_gcm::{AeadCore, Aes256Gcm, KeyInit};
use aes_gcm::aead::{Aead};
use argon2::{Argon2};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;
use crate::models::register_envelope::RegisterEnvelope;

#[wasm_bindgen]
extern "C" {
    // fn alert(s: &str);
}

// #[wasm_bindgen]
// pub fn greet(name: &str) {
//     alert(&format!("Hello, {name}!"));
// }

#[wasm_bindgen]
pub fn generate_register_envelope(master_password: String, user_email: String) -> Result<RegisterEnvelope, JsValue> {
    let master = master_password.as_bytes();
    let salt = user_email.as_bytes();

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
pub fn test_all_steps(password: String) -> Result<String, JsValue> {
    // Register
    println!("# REGISTER");
    let master = b"MasterPassword";
    println!("master : {:?}", master);

    let mut k_master = [0u8; 32];
    let salt = b"email_user";
    Argon2::default().hash_password_into(master, salt, &mut k_master).unwrap();
    println!("enc_master : {:?}", k_master);

    let mut rng = rand::thread_rng();
    let kyber_keys = pqc_kyber::keypair(&mut rng).unwrap();
    println!("public kyber : {:?}", kyber_keys.public);
    println!("secret kyber : {:?}", kyber_keys.secret);

    let cipher = Aes256Gcm::new_from_slice(&k_master).unwrap();
    let nonce1 = Aes256Gcm::generate_nonce(&mut OsRng);
    let enc_sk = cipher.encrypt(&nonce1, kyber_keys.secret.as_ref()).unwrap();

    println!("enc_sk: {:?}", enc_sk);
    //to send : public kyber + enc_sk

    // Création Entry
    println!("# CREATION ENTRY");
    // recoit public kyber
    let pwd = password.as_bytes();
    println!("pwd : {:?}", pwd);

    let mut rng = rand::thread_rng();
    let (enc_kyber, cipher_key) = pqc_kyber::encapsulate(&kyber_keys.public, &mut rng).unwrap();

    let cipher = Aes256Gcm::new_from_slice(&cipher_key).unwrap();
    let nonce2 = Aes256Gcm::generate_nonce(&mut OsRng);
    let enc_pwd = cipher.encrypt(&nonce2, pwd.as_ref()).unwrap();

    println!("cipher_key: {:?}", cipher_key);
    println!("enc_pwd: {:?}", enc_pwd);
    println!("enc_kyber: {:?}", enc_kyber);
    //to send : entry_metadata, enc_kyber + enc_pwd

    // LECTURE ENTRY
    println!("# LECTURE ENTRY");
    // Reception de entry_metadata, enc_pwd, enc_kyber, enc_sk

    let mut k_master = [0u8; 32];
    let salt = b"email_user";
    Argon2::default().hash_password_into(master, salt, &mut k_master).unwrap();
    println!("k_master : {:?}", k_master);

    let cipher = Aes256Gcm::new_from_slice(&k_master).unwrap();
    let sk = cipher.decrypt(&nonce1, enc_sk.as_ref()).unwrap();
    println!("sk: {:?}", sk);

    let cipher_key = pqc_kyber::decapsulate(&enc_kyber, &sk).unwrap();
    println!("cipher_key: {:?}", cipher_key);

    let cipher = Aes256Gcm::new_from_slice(&cipher_key).unwrap();
    let pwd = cipher.decrypt(&nonce2, enc_pwd.as_ref()).unwrap();
    println!("pwd: {:?}", pwd);

    String::from_utf8(pwd).map_err(|_|JsValue::NULL)
}

#[cfg(test)]
mod tests {
    use crate::{test_all_steps};

    #[test]
    fn test_test_all_steps() {
        let initial_password = "mot de passe";
        let pwd = test_all_steps(String::from(initial_password)).unwrap();

        assert_eq!(pwd, initial_password);
    }
}

