mod hash;

use silentpayments::bitcoin_hashes::Hash;
use js_sys::Uint8Array;
use std::str::FromStr;

use wasm_bindgen::prelude::*;
use silentpayments::utils::receiving;
use silentpayments::secp256k1::{PublicKey, SecretKey, Secp256k1};

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn compute_scripts(scan_sec_key_hex: String, spend_pub_key_hex: String, counter: u32, tweaks_data: Vec<String>) -> Vec<Uint8Array> {
    let scan_sec_key = SecretKey::from_str(scan_sec_key_hex.as_str()).unwrap();
    let spend_pub_key = PublicKey::from_str(spend_pub_key_hex.as_str()).unwrap();
    let secp = Secp256k1::new();

    let mut scripts = Vec::new();

    for data in tweaks_data {
        let data_public_key =  PublicKey::from_str(data.as_str()).unwrap();
        let shared_secret = receiving::calculate_ecdh_shared_secret(&data_public_key, &scan_sec_key);

        let tweak = hash::SharedSecretHash::from_ecdh_and_k(&shared_secret, counter);
        let tweak_key = SecretKey::from_slice(tweak.as_byte_array()).unwrap();

        let script_pub_key = spend_pub_key.add_exp_tweak(&secp, &tweak_key.into()).unwrap();

        scripts.push(taproot_output_script(script_pub_key));
    }

    scripts 
}

fn taproot_output_script(pubkey: PublicKey) -> Uint8Array {
    let x_only_pubkey = pubkey.x_only_public_key().0.serialize();

    let mut script = Vec::new();
    script.push(0x51);
    script.push(0x20);
    script.extend_from_slice(&x_only_pubkey);

    Uint8Array::from(&script[..])
}