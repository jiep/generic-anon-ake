use aes::cipher::{KeyIvInit, StreamCipher};
use ctr;

type Aes256Ctr64BE = ctr::Ctr64BE<aes::Aes256>;

pub fn prf(key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let plaintext = vec![0; 16];
    let mut counter = [0; 16];
    counter.copy_from_slice(nonce);
    let mut k = [0_u8; 32];
    k.copy_from_slice(&key[0..32]);

    let mut buf = plaintext.to_vec();
    let mut cipher = Aes256Ctr64BE::new(&k.into(), nonce.into());
    cipher.apply_keystream(&mut buf);

    buf
}
