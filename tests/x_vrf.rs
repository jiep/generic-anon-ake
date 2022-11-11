use anon_sym_ake::protocol::x_vrf::{x_vrf_eval, x_vrf_gen, x_vrf_vfy};
use qrllib::rust_wrapper::qrl::xmss_fast::XMSSFast;

#[test]
fn x_vrf_works() {
    let seed: Vec<u8> = (0..48).collect();

    let xmss_height: u8 = 8;

    let mut xmss = XMSSFast::new(seed.clone(), xmss_height, None, None, None).unwrap();

    let x: Vec<u8> = vec![1, 2, 3, 4];

    let (vk, ek) = x_vrf_gen(&seed, &xmss);

    let (y, mut pi) = x_vrf_eval(&ek, &x, &mut xmss);

    let verification = x_vrf_vfy(&vk, x.clone(), &y, &pi);

    assert!(verification);

    pi[1] += 2;

    let verification = x_vrf_vfy(&vk, x, &y, &pi);

    assert_ne!(verification, true);
}
