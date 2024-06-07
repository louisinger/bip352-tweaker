use silentpayments::bitcoin_hashes::{sha256t_hash_newtype, Hash, HashEngine};
use silentpayments::secp256k1::PublicKey;

sha256t_hash_newtype! {
    pub(crate) struct SharedSecretTag = hash_str("BIP0352/SharedSecret");

    #[hash_newtype(forward)]
    pub(crate) struct SharedSecretHash(_);
}

impl SharedSecretHash {
    pub(crate) fn from_ecdh_and_k(ecdh: &PublicKey, k: u32) -> SharedSecretHash {
        let mut eng = SharedSecretHash::engine();
        eng.input(&ecdh.serialize());
        eng.input(&k.to_be_bytes());
        SharedSecretHash::from_engine(eng)
    }
}
