use ecies::{decrypt, encrypt, utils::generate_keypair, PublicKey, SecretKey};

pub fn ccapke_gen() -> (PublicKey, SecretKey) {
    let (sk, pk) = generate_keypair();

    (pk, sk)
}

pub fn ccapke_enc(pk: &PublicKey, m: &[u8]) -> Vec<u8> {
    let pk = &pk.serialize();
    encrypt(pk, m).unwrap()
}

pub fn ccapke_dec(sk: &SecretKey, ct: &[u8]) -> Vec<u8> {
    let sk = &sk.serialize();
    decrypt(sk, ct).unwrap()
}
