use lb_vrf::lbvrf::{Proof, LBVRF};
use lb_vrf::param::Param;
use lb_vrf::poly256::Poly256;
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

pub fn vrf_serialize_pi(z: [Poly256; 9], c: Poly256) -> ([Vec<u8>; 9], Vec<u8>) {
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

    (buf_z, buf_c)
}

#[cfg(test)]
mod tests {
    use lb_vrf::{lbvrf::LBVRF, VRF};

    use crate::vrf::{vrf_gen_seed_param, vrf_keypair};

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
}
