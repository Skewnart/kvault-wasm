# Kvault (WASM edition)

This repository contains the WebAssembly cryptography module used by Kvault. It exposes password-encryption operations to JavaScript through `wasm-bindgen`.

## Related projects

- Frontend: [skewnart/kvault-front](https://github.com/skewnart/kvault-front)
- Backend: [skewnart/kvault-back](https://github.com/skewnart/kvault-back)

The Kvault frontend already includes the compiled WebAssembly version it needs. You do not need to build this repository separately to run or use the frontend.

## What this module does

- `generate_register_envelope(master_password)` derives a key from the master password, generates a Kyber key pair, and encrypts the private key. It returns a `RegisterEnvelope` containing the master salt, encrypted private key, public key, and nonce.
- `create_encoded(plain_text, pk)` encapsulates a key using the public key, encrypts the text, and returns an `Encoded` value containing the ciphertext, Kyber encapsulation, and nonce.
- `read_encoded(...)` decrypts the private key using the master password, decapsulates the key, and decrypts the text.

The `RegisterEnvelope` and `Encoded` fields are byte arrays exposed to JavaScript. Store and pass them back unchanged when calling the corresponding operations.

## Wasm build commands

Install the Rust toolchain and the WebAssembly target, then install the `wasm-bindgen` CLI:

```sh
rustup update
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli
```

Build and generate JavaScript bindings for development:

```sh
cargo build --target wasm32-unknown-unknown
wasm-bindgen target/wasm32-unknown-unknown/debug/kvault_wasm.wasm --out-dir wasm_pkg --target web
```

Build and generate JavaScript bindings for release:

```sh
cargo build --target wasm32-unknown-unknown --release
wasm-bindgen target/wasm32-unknown-unknown/release/kvault_wasm.wasm --out-dir wasm_pkg --target web
```

Run the Rust tests with:

```sh
cargo test
```