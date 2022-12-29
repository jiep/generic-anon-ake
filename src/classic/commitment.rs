use crate::common::utils::get_random_key32;
use sha2::{Digest, Sha256};

// Output: commitment := H(r || x) and open := (x, r)
pub fn comm(x: &[u8]) -> (Vec<u8>, (Vec<u8>, Vec<u8>)) {
    let r: Vec<u8> = get_random_key32();
    let to_commit: Vec<u8> = [r.to_vec(), x.to_vec()].concat();

    let mut hasher = Sha256::new();
    hasher.update(to_commit);
    let commitment: Vec<u8> = hasher.finalize().to_vec();
    (commitment, (x.to_vec(), r))
}

pub fn comm_vfy(comm: &[u8], open: &(Vec<u8>, Vec<u8>)) -> bool {
    let (x, r) = open;
    let to_commit: Vec<u8> = [r.to_vec(), x.to_vec()].concat();

    let mut hasher = Sha256::new();
    hasher.update(to_commit);
    let commitment: Vec<u8> = hasher.finalize().to_vec();

    let are_equal: bool = commitment.iter().zip(comm.iter()).all(|(a, b)| a == b);

    are_equal
}
