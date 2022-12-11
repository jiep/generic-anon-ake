use anon_sym_ake::protocol::{prf::prf, utils::get_random_key32};

#[test]
fn prf_works() {
    let key: Vec<u8> = get_random_key32();
    let mut counter = 0_u128;
    let nonce = counter.to_be_bytes();
    counter += 1;
    let nonce2 = counter.to_be_bytes();
    let n = prf(&key, &nonce);
    let n2 = prf(&key, &nonce2);

    assert_ne!(n, n2);
    assert!(n.len() == 16);
    assert!(n2.len() == 16);
}
