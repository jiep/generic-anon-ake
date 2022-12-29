use generic_anon_ake::{
    classic::sig::{sig_gen, sig_sign, sig_vry},
    common::utils::get_random_key32,
};

#[test]
fn sig_classic_works() {
    let (pk, sk) = sig_gen();
    let (pk2, sk2) = sig_gen();

    let m = get_random_key32();
    let sig = sig_sign(&sk, &m);
    let sig2 = sig_sign(&sk2, &m);

    let ver = sig_vry(&pk, &m, &sig);
    let ver2 = sig_vry(&pk2, &m, &sig);
    let ver3 = sig_vry(&pk, &m, &sig2);

    assert!(ver);
    assert!(!ver2);
    assert!(!ver3);
}
