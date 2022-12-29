use aes_gcm::aead::rand_core;
use k256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};

use k256::ecdsa::signature::Verifier;

use rand_core::OsRng;

pub fn sig_gen() -> (VerifyingKey, SigningKey) {
    let sk = SigningKey::random(&mut OsRng);
    let pk = VerifyingKey::from(&sk);

    (pk, sk)
}

pub fn sig_sign(sk: &SigningKey, m: &[u8]) -> Signature {
    let signature: Signature = sk.sign(m);

    signature
}

pub fn sig_vry(pk: &VerifyingKey, m: &[u8], signature: &Signature) -> bool {
    pk.verify(m, signature).is_ok()
}
