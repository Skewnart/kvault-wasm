# K-Vault (WASM edition)

K-Vault README file will come with its 1st major version.<br>
See you soon !

## Wasm build commands

````
rustup update
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli

# debug :
cargo build --target wasm32-unknown-unknown
wasm-bindgen target/wasm32-unknown-unknown/debug/kvault_wasm.wasm --out-dir wasm_pkg --target web"

# release :
cargo build --target wasm32-unknown-unknown --release
wasm-bindgen target/wasm32-unknown-unknown/release/kvault_wasm.wasm --out-dir wasm_pkg --target web"
````