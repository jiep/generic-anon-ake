use generic_anon_ake::common::{prf::prf, utils::get_random_key32};

#[test]
fn prf_works() {
    for _ in 0..1000 {
        let key: Vec<u8> = get_random_key32();
        let mut counter = 123_u128;
        let nonce = counter.to_be_bytes();
        counter += 1;
        let nonce2 = counter.to_be_bytes();
        let n = prf(&key, &nonce);
        let n2 = prf(&key, &nonce2);
        let n3 = prf(&key, &nonce);

        assert_ne!(n, n2);
        assert_eq!(n, n3);
        assert!(n.len() == 16);
        assert!(n2.len() == 16);
        assert!(n3.len() == 16);
    }
}
