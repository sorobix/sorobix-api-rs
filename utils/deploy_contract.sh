rm -rf ./sorobix_temp

cargo new --lib sorobix_temp

cd sorobix_temp

echo """
[package]
name = \"sorobix_temp\"
version = \"0.1.0\"
edition = \"2021\"
[lib]
crate-type = [\"cdylib\"]
[dependencies]
soroban-sdk = { version = \"0.7.0\"}
[profile.release]
opt-level = \"z\"
overflow-checks = true
debug = 0
strip = \"symbols\"
debug-assertions = false
panic = \"abort\"
codegen-units = 1
lto = true
[profile.release-with-logs]
inherits = \"release\"
debug-assertions = true
""" > Cargo.toml

echo $1 > src/lib.rs

cargo build --target wasm32-unknown-unknown --release

soroban contract deploy \
    --wasm target/wasm32-unknown-unknown/release/sorobix_temp.wasm \
    --source $2 \
    --rpc-url https://rpc-futurenet.stellar.org:443 \
    --network-passphrase 'Test SDF Future Network ; October 2022'