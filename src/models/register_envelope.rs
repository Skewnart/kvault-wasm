use wasm_bindgen::prelude::*;

#[wasm_bindgen(getter_with_clone)]
pub struct RegisterEnvelope {
    pub master_salt: Vec<u8>,
    pub enc_sk: Vec<u8>,
    pub pk: Vec<u8>,
    pub sk_nonce: Vec<u8>
}

#[wasm_bindgen]
impl RegisterEnvelope {
    pub fn new(master_salt: Vec<u8>, enc_sk: Vec<u8>, pk: Vec<u8>, sk_nonce: Vec<u8>) -> Self {
        Self {
            master_salt,
            enc_sk,
            pk,
            sk_nonce
        }
    }
}
