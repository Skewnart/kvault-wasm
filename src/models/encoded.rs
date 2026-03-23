use wasm_bindgen::prelude::*;

#[wasm_bindgen(getter_with_clone)]
pub struct Encoded {
    pub encoded: Vec<u8>,
    pub enc_kyber: Vec<u8>,
    pub enc_nonce: Vec<u8>
}

#[wasm_bindgen]
impl Encoded {
    pub fn new(encoded: Vec<u8>, enc_kyber: Vec<u8>, enc_nonce: Vec<u8>) -> Self {
        Self {
            encoded,
            enc_kyber,
            enc_nonce
        }
    }
}
