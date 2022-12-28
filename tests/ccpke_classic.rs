use anon_sym_ake::{
    classic::ccapke::{ccapke_dec, ccapke_enc, ccapke_gen},
    common::utils::get_random_key32,
};

#[test]
fn ccapke_classic_works() {
    let (pk, sk) = ccapke_gen();

    let m = get_random_key32();
    let ct = ccapke_enc(&pk, &m);
    let ct2 = ccapke_enc(&pk, &m);

    let m2 = ccapke_dec(&sk, &ct);

    assert_eq!(m, m2);
    assert_ne!(ct, ct2);
}
