use qrllib::rust_wrapper::qrl::{
    xmss_base::{Sign, XMSSBase, XMSSBaseTrait},
    xmss_fast::XMSSFast,
};
use sha3::{Digest, Sha3_256};

pub fn x_vrf_gen(_seed: &[u8], xmss: &XMSSFast) -> (Vec<u8>, Vec<u8>) {
    (xmss.get_pk(), xmss.get_sk().to_vec())
}

pub fn x_vrf_eval(_ek: &[u8], x: &Vec<u8>, xmss: &mut XMSSFast) -> (Vec<u8>, Vec<u8>) {
    let pi = xmss.sign(x).unwrap();
    let mut hasher = Sha3_256::new();
    hasher.update([pi.clone(), x.to_vec()].concat());
    let y: Vec<u8> = hasher.finalize().to_vec();

    (y, pi)
}

pub fn x_vrf_vfy(vk: &Vec<u8>, mut x: Vec<u8>, y: &[u8], pi: &Vec<u8>) -> bool {
    let mut verification = false;
    if XMSSBase::verify(&mut x, &pi.to_owned(), vk, None).is_ok() {
        let mut hasher = Sha3_256::new();
        hasher.update([pi.to_vec(), x.to_vec()].concat());
        let hashed: Vec<u8> = hasher.finalize().to_vec();
        if hashed == y.to_vec() {
            verification = true;
        }
    }
    verification
}
