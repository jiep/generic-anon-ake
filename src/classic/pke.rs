use ecies::{utils::generate_keypair, PublicKey, SecretKey};
use pke_ecies::{decrypt, encrypt};

pub fn pke_gen() -> (PublicKey, SecretKey) {
    let (sk, pk) = generate_keypair();

    (pk, sk)
}

pub fn pke_enc(pk: &PublicKey, m: &[u8], r: &[u8]) -> Vec<u8> {
    let sk = SecretKey::parse_slice([r, r].concat().as_slice()).unwrap();
    let pk = &pk.serialize();
    encrypt(pk, m, &(sk, PublicKey::from_secret_key(&sk))).unwrap()
}

pub fn pke_dec(sk: &SecretKey, ct: &[u8]) -> Vec<u8> {
    let sk = &sk.serialize();
    decrypt(sk, ct).unwrap()
}

pub fn check_ciphertext(c1: &[u8], c2: &[u8]) -> bool {
    let are_equal0: bool = c1
        .to_owned()
        .iter()
        .zip(c2.to_owned().iter())
        .all(|(a, b)| a == b);

    are_equal0
}
