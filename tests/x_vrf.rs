use anon_sym_ake::protocol::x_vrf::{x_vrf_eval, x_vrf_gen, x_vrf_vfy};
use qrllib::rust_wrapper::xmss_alt::{
    algsxmss_fast::{BDSState, TreeHashInst},
    xmss_common::XMSSParams,
};

#[test]
fn x_vrf_works() {
    let h: u8 = 4;
    let n: u32 = 48;
    let mut seed: [u8; 48] = [0; 48];

    println!("before keygen");

    let k: u32 = 2;
    let stack = vec![0; (h as usize + 1) * n as usize];
    let stackoffset: u32 = 0;
    let stacklevels: Vec<u8> = vec![0; h as usize + 1];
    let auth: Vec<u8> = vec![0; (h as usize) * n as usize];
    let keep: Vec<u8> = vec![0; (h >> 1) as usize * n as usize];
    let treehash: Vec<TreeHashInst> = vec![TreeHashInst::default(); h as usize - k as usize];
    let retain: Vec<u8> = vec![0; ((1 << k) - k - 1) as usize * n as usize];

    let mut state = BDSState {
        stack,
        stackoffset,
        stacklevels,
        auth,
        keep,
        treehash,
        retain,
        next_leaf: 0,
    };

    let mut params = XMSSParams::new(32, h.into(), 16, 2).unwrap();

    let x: Vec<u8> = (0..32).collect();

    let (vk, mut ek) = x_vrf_gen(&mut params, &mut state, &mut seed);

    let (y, mut pi) = x_vrf_eval(&mut ek, &x, &params, &mut state);

    let verification = x_vrf_vfy(&vk, &mut x.to_vec(), &y, &pi, &params);

    assert!(verification);

    pi[1] += 2;

    let verification = x_vrf_vfy(&vk, &mut x.to_vec(), &y, &pi, &params);

    assert_ne!(verification, true);
}
