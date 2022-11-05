use aes_gcm::aes::cipher::generic_array::{
    typenum::{UInt, UTerm, B0, B1},
    GenericArray,
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

use oqs::kem::{self, Ciphertext};

use crate::utils::get_nonce;

#[allow(clippy::type_complexity)]
pub fn pke_enc(
    kem: &kem::Kem,
    pk: &kem::PublicKey,
    m: &Vec<u8>,
) -> (
    Ciphertext,
    Vec<u8>,
    GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
) {
    let (ct, k) = kem.encapsulate(pk).unwrap();

    let cipher = Aes256Gcm::new_from_slice(k.into_vec().as_slice()).unwrap();
    let nonce = get_nonce();
    let iv = Nonce::from_slice(nonce.as_slice());
    let ciphertext = cipher.encrypt(iv, m.as_slice()).unwrap();

    (ct, ciphertext, *iv)
}

#[allow(clippy::type_complexity)]
pub fn pke_dec(
    kem: &kem::Kem,
    sk: kem::SecretKey,
    ct: &Ciphertext,
    ciphertext: &Vec<u8>,
    iv: &GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
) -> Vec<u8> {
    let k = kem.decapsulate(&sk, ct).unwrap();
    let cipher = Aes256Gcm::new_from_slice(k.into_vec().as_slice()).unwrap();
    let plaintext = cipher.decrypt(iv, ciphertext.as_ref()).unwrap();

    plaintext
}

#[cfg(test)]
mod tests {
    use oqs::kem;
    use crate::pke::{pke_enc, pke_dec};


    #[test]
    fn pke_works() {
        let kemalg = kem::Kem::new(kem::Algorithm::Kyber512).unwrap();
        let (pk, sk) = kemalg.keypair().unwrap();
        let m: Vec<u8> = vec![3, 1, 4, 15, 9, 65];
        let (ct_kem, ct_dem, iv_tag) = pke_enc(&kemalg, &pk, &m);

        let m_decrypted = pke_dec(&kemalg, sk, &ct_kem, &ct_dem, &iv_tag);

        assert_eq!(m, m_decrypted);
    }
}