use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

use oqs::kem::{self, Ciphertext};

use super::protocol::TagType;

pub fn check_ciphertext(
    c1: &(Ciphertext, Vec<u8>, TagType),
    c2: &(Ciphertext, Vec<u8>, TagType),
) -> bool {
    let are_equal0: bool =
        c1.0.clone()
            .into_vec()
            .iter()
            .zip(c2.0.clone().into_vec().iter())
            .all(|(a, b)| a == b);
    let are_equal1: bool = c1.1.iter().zip(c2.1.iter()).all(|(a, b)| a == b);
    let are_equal2: bool = c1.2.iter().zip(c2.2.iter()).all(|(a, b)| a == b);

    are_equal0 && are_equal1 && are_equal2
}

pub fn pke_enc(
    kem: &kem::Kem,
    pk: &kem::PublicKey,
    m: &Vec<u8>,
    r: &Vec<u8>,
    nonce: &Vec<u8>,
) -> (Ciphertext, Vec<u8>, TagType) {

    let (ct, k) = kem.encapsulate(pk, r).unwrap();
    let cipher = Aes256Gcm::new_from_slice(k.clone().into_vec().as_slice()).unwrap();
    let iv = Nonce::from_slice(nonce.as_slice());
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
