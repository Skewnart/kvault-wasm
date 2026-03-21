use wasm_bindgen::prelude::*;

#[wasm_bindgen(getter_with_clone)]
pub struct Entry {
    pub enc_pwd: Vec<u8>,
    pub enc_kyber: Vec<u8>,
    pub pwd_nonce: Vec<u8>
}

#[wasm_bindgen]
impl Entry {
    pub fn new(enc_pwd: Vec<u8>, enc_kyber: Vec<u8>, pwd_nonce: Vec<u8>) -> Self {
        Self {
            enc_pwd,
            enc_kyber,
            pwd_nonce
        }
    }
}
