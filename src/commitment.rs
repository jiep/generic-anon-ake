use sha3::{Digest, Sha3_256};
use crate::utils::get_random_key32;

// Output: commitment and open
pub fn comm(x: &mut Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let open: Vec<u8> = get_random_key32();
    let mut to_commit: Vec<u8> = open.clone();
    to_commit.append(x);

    let mut hasher = Sha3_256::new();
    hasher.update(to_commit);
    let commitment: Vec<u8> = hasher.finalize().to_vec();
    (commitment, open)
}

pub fn comm_vfy(comm: &[u8], open: &[u8], x: &mut Vec<u8>) -> bool {
    let mut to_commit: Vec<u8> = open.to_owned();
    to_commit.append(x);

    let mut hasher = Sha3_256::new();
    hasher.update(to_commit);
    let commitment: Vec<u8> = hasher.finalize().to_vec();

    let are_equal: bool = commitment.iter().zip(comm.iter()).all(|(a, b)| a == b);

    are_equal
}
