use anon_sym_ake::protocol::{
    pke::{pke_dec, pke_enc},
    utils::get_nonce,
};
use oqs::kem;

#[test]
fn pke_works() {
    let kemalg = kem::Kem::new(kem::Algorithm::Kyber512).unwrap();
    let (pk, sk) = kemalg.keypair().unwrap();
    let m: Vec<u8> = vec![3, 1, 4, 15, 9, 65];
    let r: Vec<u8> = (0_u8..32_u8).collect();
    let nonce: Vec<u8> = get_nonce();
    let (ct_kem, ct_dem, iv_tag) = pke_enc(&kemalg, &pk, &m, &r, &nonce);
    let (ct_kem2, ct_dem2, iv_tag2) = pke_enc(&kemalg, &pk, &m, &r, &nonce);

    let m_decrypted = pke_dec(&kemalg, sk, &ct_kem, &ct_dem, &iv_tag);
    assert_eq!(m, m_decrypted);
    assert_eq!(ct_kem, ct_kem2);
    assert_eq!(ct_dem, ct_dem2);
    assert_eq!(iv_tag, iv_tag2);
}
