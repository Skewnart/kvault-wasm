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
#[cfg(test)]
mod tests {
    use crate::{generate_keypair, test_all_steps};

    #[test]
    fn test_generate_keypair() {
        generate_keypair();
    }
}

