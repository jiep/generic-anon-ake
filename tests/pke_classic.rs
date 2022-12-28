use anon_sym_ake::{
    classic::pke::{pke_dec, pke_enc, pke_gen},
    common::utils::get_random_key32,
};
use pke_ecies::utils::generate_keypair;

#[test]
fn pke_classic_works() {
    let (pk, sk) = pke_gen();

    let m = get_random_key32();
    let r = generate_keypair();
    let ct = pke_enc(&pk, &m, &r);
    let ct2 = pke_enc(&pk, &m, &r);

    assert_eq!(ct, ct2);

    let m2 = pke_dec(&sk, &ct);

    assert_eq!(m, m2);
}
