use lb_vrf::lbvrf::{Proof, LBVRF};
use lb_vrf::param::Param;
use lb_vrf::poly256::Poly256;
use lb_vrf::poly32::Poly32;
use lb_vrf::VRF;
use rand::RngCore;

pub fn vrf_gen_seed_param() -> ([u8; 32], Param) {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];

    rng.fill_bytes(&mut seed);
    let param: Param = <LBVRF as VRF>::paramgen(seed).unwrap();

    (seed, param)
}

pub fn vrf_keypair(
    seed: &[u8; 32],
    param: &Param,
) -> (lb_vrf::keypair::PublicKey, lb_vrf::keypair::SecretKey) {
    let (pk, sk) = <LBVRF as VRF>::keygen(*seed, *param).unwrap();

    (pk, sk)
}

pub fn vrf_serialize_y_from_proof(p: &Proof) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();

    lb_vrf::serde::Serdes::serialize(&p.v, &mut buf).unwrap();

    buf
}

fn vrf_get_pi_from_proof(p: &Proof) -> ([Poly256; 9], Poly256) {
    (p.z, p.c)
}

pub fn vrf_serialize_pi(p: &Proof) -> (Vec<u8>, [Vec<u8>; 9]) {
    let (z, c) = vrf_get_pi_from_proof(p);

    let mut buf_c: Vec<u8> = Vec::new();
    let mut buf_z: [Vec<u8>; 9] = [
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ];

    lb_vrf::serde::Serdes::serialize(&c, &mut buf_c).unwrap();

    for i in 0..9 {
        lb_vrf::serde::Serdes::serialize(&z[i], &mut buf_z[i]).unwrap();
    }

    (buf_c, buf_z)
}
