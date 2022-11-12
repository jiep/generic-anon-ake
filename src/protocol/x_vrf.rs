use qrllib::rust_wrapper::xmss_alt::{
    algsxmss_fast::{xmss_fast_gen_keypair, xmss_fast_sign_msg, BDSState},
    hash_functions::HashFunction,
    xmss_common::{xmss_verify_sig, XMSSParams},
};
use sha3::{Digest, Sha3_256};

pub fn x_vrf_gen(
    params: &XMSSParams,
    state: &mut BDSState,
    seed: &mut [u8; 48],
) -> (Vec<u8>, Vec<u8>) {
    let mut pk: [u8; 64] = [0; 64];
    let mut sk: [u8; 4 + 4 * 32] = [0; 4 + 4 * 32];

    let _x = xmss_fast_gen_keypair(
        &HashFunction::Shake128,
        params,
        &mut pk,
        &mut sk,
        state,
        seed,
    )
    .is_ok();

    (pk.to_vec(), sk.to_vec())
}

pub fn x_vrf_eval(
    ek: &mut [u8],
    x: &Vec<u8>,
    params: &XMSSParams,
    state: &mut BDSState,
) -> (Vec<u8>, Vec<u8>) {
    let mut pi: [u8; 10000] = [0; 10000];

    let _x = xmss_fast_sign_msg(
        &HashFunction::Shake128,
        params,
        ek,
        state,
        &mut pi,
        x,
        x.len(),
    );

    let mut hasher = Sha3_256::new();
    hasher.update([pi.to_vec(), x.to_vec()].concat());
    let y: Vec<u8> = hasher.finalize().to_vec();

    (y, pi.to_vec())
}

pub fn x_vrf_vfy(vk: &[u8], x: &mut [u8], y: &[u8], pi: &[u8], params: &XMSSParams) -> bool {
    let mut verification = false;
    let h = 4;
    if xmss_verify_sig(
        &HashFunction::Shake128,
        &params.wots_par,
        x,
        x.len(),
        pi,
        vk,
        h,
    ) == 0
    {
        let mut hasher = Sha3_256::new();
        hasher.update([pi.to_vec(), x.to_vec()].concat());
        let hashed: Vec<u8> = hasher.finalize().to_vec();
        if hashed == y.to_vec() {
            verification = true;
        }
    }
    verification
}
