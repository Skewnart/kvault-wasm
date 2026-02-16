use aes_gcm::{AeadCore, Aes256Gcm, KeyInit};
use aes_gcm::aead::{Aead};
use argon2::{Argon2};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet(name: &str) {
    alert(&format!("Hello, {name}!"));
}

#[wasm_bindgen]
pub fn generate_keypair() {
    let mut rng = rand::thread_rng();

    let keys = pqc_kyber::keypair(&mut rng).unwrap();
    println!("public : {:?}", keys.public);
    println!("secret : {:?}", keys.secret);
}

#[wasm_bindgen]
pub fn test_all_steps() {
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
    let pwd = b"mot_de_passe";
    println!("pwd : {:?}", pwd);

    let mut rng = rand::thread_rng();
    let (encrypted_kyber, cipher_key) = pqc_kyber::encapsulate(&kyber_keys.public, &mut rng).unwrap();

    let cipher = Aes256Gcm::new_from_slice(&cipher_key).unwrap();
    let nonce2 = Aes256Gcm::generate_nonce(&mut OsRng);
    let enc_pwd = cipher.encrypt(&nonce2, pwd.as_ref()).unwrap();

    println!("cipher_key: {:?}", cipher_key);
    println!("enc_pwd: {:?}", enc_pwd);
    println!("encrypted_kyber: {:?}", encrypted_kyber);
    //to send : entry_metadata, encrypted_kyber + enc_pwd

    // LECTURE ENTRY
    println!("# LECTURE ENTRY");
    // Reception de entry_metadata, enc_pwd, encrypted_kyber, enc_sk

    let mut k_master = [0u8; 32];
    let salt = b"email_user";
    Argon2::default().hash_password_into(master, salt, &mut k_master).unwrap();
    println!("k_master : {:?}", k_master);

    let cipher = Aes256Gcm::new_from_slice(&k_master).unwrap();
    let sk = cipher.decrypt(&nonce1, enc_sk.as_ref()).unwrap();
    println!("sk: {:?}", sk);

    let cipher_key = pqc_kyber::decapsulate(&encrypted_kyber, &sk).unwrap();
    println!("cipher_key: {:?}", cipher_key);

    let cipher = Aes256Gcm::new_from_slice(&cipher_key).unwrap();
    let pwd = cipher.decrypt(&nonce2, enc_pwd.as_ref()).unwrap();
    println!("pwd: {:?}", pwd);
}

#[cfg(test)]
mod tests {
    use crate::{generate_keypair, test_all_steps};

    #[test]
    fn test_generate_keypair() {
        generate_keypair();
    }

    #[test]
    fn test_test_all_steps() {
        test_all_steps();
    }
}

