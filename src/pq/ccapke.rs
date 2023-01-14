use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

use oqs::kem::{self, Ciphertext};

use crate::common::utils::get_nonce;

use super::protocol::TagType;

pub fn ccapke_enc(
    kem: &kem::Kem,
    pk: &kem::PublicKey,
    m: &Vec<u8>,
) -> (Ciphertext, Vec<u8>, TagType) {
    let r = kem.get_randomness().unwrap();
    let (ct, k) = kem.encapsulate(pk, &r).unwrap();
    let cipher = Aes256Gcm::new_from_slice(k.into_vec().as_slice()).unwrap();
    let nonce = get_nonce();
    let iv = Nonce::from_slice(nonce.as_slice());
    let ciphertext = cipher.encrypt(iv, m.as_slice()).unwrap();

    (ct, ciphertext, *iv)
}

pub fn ccapke_dec(
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
