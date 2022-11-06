use lb_vrf::{lbvrf::LBVRF, VRF};

use anon_sym_ake::protocol::vrf::{vrf_gen_seed_param, vrf_keypair};

#[test]
fn vrf_works() {
    let (seed, param) = vrf_gen_seed_param();
    let message: Vec<u8> = vec![1, 2, 3, 4, 5];

    assert_eq!(seed.len(), 32);
    assert_ne!(seed, [0u8; 32]);

    let (pk, sk) = vrf_keypair(&seed, &param);

    let proof = <LBVRF as VRF>::prove(&message, param, pk, sk, seed).unwrap();

    let res = <LBVRF as VRF>::verify(&message, param, pk, proof).unwrap();

    assert!(res.is_some());
    assert_eq!(res.unwrap(), proof.v);
}
