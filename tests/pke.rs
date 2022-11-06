use anon_sym_ake::protocol::pke::{pke_dec, pke_enc};
use oqs::kem;

#[test]
fn pke_works() {
    let kemalg = kem::Kem::new(kem::Algorithm::Kyber512).unwrap();
    let (pk, sk) = kemalg.keypair().unwrap();
    let m: Vec<u8> = vec![3, 1, 4, 15, 9, 65];
    let (ct_kem, ct_dem, iv_tag) = pke_enc(&kemalg, &pk, &m);

    let m_decrypted = pke_dec(&kemalg, sk, &ct_kem, &ct_dem, &iv_tag);

    assert_eq!(m, m_decrypted);
}
