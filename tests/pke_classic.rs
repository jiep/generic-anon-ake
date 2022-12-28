use anon_sym_ake::{
    classic::pke::{pke_dec, pke_enc, pke_gen},
    common::utils::get_random_key32,
};

#[test]
fn pke_classic_works() {
    let (pk, sk) = pke_gen();

    let m = get_random_key32();
    let r: Vec<u8> = (0_u8..16_u8).collect();
    let ct = pke_enc(&pk, &m, &r.as_slice());
    let ct2 = pke_enc(&pk, &m, &r);

    assert_eq!(ct, ct2);

    let m2 = pke_dec(&sk, &ct);

    assert_eq!(m, m2);
}
