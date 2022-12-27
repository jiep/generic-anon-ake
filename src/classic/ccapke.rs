use ecies::{decrypt, encrypt, utils::generate_keypair, PublicKey, SecretKey};


pub fn ccapke_gen() -> (PublicKey, SecretKey) {
    let (sk, pk) = generate_keypair();

    (pk, sk)
}

pub fn ccapke_enc(pk: &PublicKey, m: &Vec<u8>) -> Vec<u8> {
    let pk = &pk.serialize();
    let ct = encrypt(pk, m).unwrap();

    ct
}

pub fn ccapke_dec(sk: &SecretKey, ct: &Vec<u8>) -> Vec<u8> {
    let sk = &sk.serialize();
    let m = decrypt(sk, &ct).unwrap();

    m
}