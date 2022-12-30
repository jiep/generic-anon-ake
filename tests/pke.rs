use generic_anon_ake::{
    common::{prf::prf, utils::get_random_key32},
    pq::{
        pke::{check_ciphertext, pke_dec, pke_enc},
        protocol::TagType,
    },
};
use oqs::kem::{self, Ciphertext, PublicKey};

#[test]
fn pke_works() {
    for _ in (0_u16..2000_u16).collect::<Vec<u16>>().iter() {
        let kemalg = kem::Kem::new(kem::Algorithm::Kyber1024).unwrap();
        let (pk, sk) = kemalg.keypair().unwrap();
        let m: Vec<u8> = get_random_key32();
        let r: Vec<u8> = get_random_key32();
        let r1: Vec<u8> = get_random_key32();
        let (ct_kem, ct_dem, iv_tag) = pke_enc(&kemalg, &pk, &m, &r);
        let (ct_kem2, ct_dem2, iv_tag2) = pke_enc(&kemalg, &pk, &m, &r);
        let ct1 = pke_enc(&kemalg, &pk, &m, &r);
        let ct2 = pke_enc(&kemalg, &pk, &m, &r);
        let ct3 = pke_enc(&kemalg, &pk, &m, &r1);

        let m_decrypted = pke_dec(&kemalg, sk, &ct_kem, &ct_dem, &iv_tag);
        assert_eq!(m, m_decrypted);
        assert_eq!(ct_kem, ct_kem2);
        assert_eq!(ct_dem, ct_dem2);
        assert_eq!(iv_tag, iv_tag2);
        assert!(check_ciphertext(&ct1, &ct2));
        assert!(!check_ciphertext(&ct1, &ct3));
    }
}

#[test]
fn pke_is_deterministic() {
    let kemalg = kem::Kem::new(kem::Algorithm::Kyber1024).unwrap();

    let (pk, sk) = kemalg.keypair().unwrap();

    let r = get_random_key32();
    let m = get_random_key32();

    let ct = pke_enc(&kemalg, &pk, &m, &r);
    let ct2 = pke_enc(&kemalg, &pk, &m, &r);
    let m2 = pke_dec(&kemalg, sk, &ct2.0, &ct.1, &ct.2);

    assert_eq!(ct, ct2);
    assert_eq!(m, m2);
}
