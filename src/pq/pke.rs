use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

use oqs::kem::{self, Ciphertext};
use sha3::{Digest, Sha3_256};

use super::protocol::TagType;

fn check_equal(v1: &[u8], v2: &[u8]) -> bool {
    v1.to_vec()
        .iter()
        .zip(v2.to_vec().iter())
        .all(|(a, b)| a == b)
}

pub fn check_ciphertext(
    c1: &(Ciphertext, Vec<u8>, TagType),
    c2: &(Ciphertext, Vec<u8>, TagType),
) -> bool {
    let are_equal0: bool = check_equal(&c1.0.clone().into_vec(), &c2.0.clone().into_vec());
    let are_equal1: bool = check_equal(&c1.1, &c2.1);
    let are_equal2: bool = check_equal(&c1.2, &c2.2);

    are_equal0 && are_equal1 && are_equal2
}

pub fn pke_enc(
    kem: &kem::Kem,
    pk: &kem::PublicKey,
    m: &Vec<u8>,
    r: &Vec<u8>,
) -> (Ciphertext, Vec<u8>, TagType) {
    let mut hasher = Sha3_256::new();
    hasher.update(r);
    let nonce = hasher.finalize().to_vec();
    let (ct, k) = kem.encapsulate(pk, r).unwrap();
    let cipher = Aes256Gcm::new_from_slice(k.into_vec().as_slice()).unwrap();
    let iv = Nonce::from_slice(&nonce[0..12]);
    let ciphertext = cipher.encrypt(iv, m.as_slice()).unwrap();

    (ct, ciphertext, *iv)
}

pub fn pke_dec(
    kem: &kem::Kem,
    sk: kem::SecretKey,
    ct: &Ciphertext,
    ciphertext: &Vec<u8>,
    iv: &TagType,
) -> Vec<u8> {
    let k = kem.decapsulate(&sk, ct).unwrap();
    let cipher = Aes256Gcm::new_from_slice(k.into_vec().as_slice()).unwrap();
    let plaintext = cipher.decrypt(iv, ciphertext.as_ref()).unwrap();

    plaintext
}
