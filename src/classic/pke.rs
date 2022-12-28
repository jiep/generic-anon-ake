use ecies::{utils::generate_keypair, PublicKey, SecretKey};
use pke_ecies::{decrypt, encrypt};

pub fn pke_gen() -> (PublicKey, SecretKey) {
    let (sk, pk) = generate_keypair();

    (pk, sk)
}

pub fn pke_enc(pk: &PublicKey, m: &[u8], r: &(SecretKey, PublicKey)) -> Vec<u8> {
    let pk = &pk.serialize();
    encrypt(pk, m, r).unwrap()
}

pub fn pke_dec(sk: &SecretKey, ct: &[u8]) -> Vec<u8> {
    let sk = &sk.serialize();
    decrypt(sk, ct).unwrap()
}
