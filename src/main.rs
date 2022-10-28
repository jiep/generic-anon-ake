use vrf::VRF;
use vrf::openssl::{CipherSuite, ECVRF};
use sha3::{Digest, Sha3_256};
//use vrf::VRF;

use rand::thread_rng;
use rand::Rng;

use oqs::{sig, kem};

//use aes_gcm::{
//    aead::{Aead, KeyInit, OsRng},
//    Aes256Gcm,
//    Nonce, // Or `Aes128Gcm`
//};

fn get_random_key32() ->  Vec<u8>{
    let mut x = vec![0; 32];
    thread_rng().try_fill(&mut x[..]).expect("Error while generating random number!");
    return x;
}

fn print_hex(arr: Vec<u8>, name: &str) {
    println!("{:}: 0x{:}", name, hex::encode(&arr));
}

// Output: commitment and open
fn comm(x: &mut Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let open: Vec<u8> = get_random_key32();
    let mut to_commit: Vec<u8> = open.clone();
    to_commit.append(x);

    let mut hasher = Sha3_256::new();
    hasher.update(to_commit);
    let commitment: Vec<u8> = hasher.finalize().to_vec();
    return (commitment, open);
}

fn xor(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
    let z: Vec<_> = x.iter().zip(y).map(|(a, b)| a ^ b).collect();
    z 
}

fn main() {
    // 0. Registration
    println!("0. Registration");
    let users:u16 = 10;

    let mut users_keys:Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    // Init VRF - Not Post Quantum with this library
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();

    // Init PQ signature scheme 
    let sigalg = sig::Sig::new(sig::Algorithm::Dilithium2).unwrap();
    let (pk_s, sk_s) = sigalg.keypair().unwrap();
    print!("[S] ");
    print_hex(pk_s.into_vec(), "pk_S");
    print!("[S] ");
    print_hex(sk_s.into_vec(), "sk_S");

    for i in 0..users {
        println!("User {:}", i);
        let ek =  get_random_key32();
        let vk = vrf.derive_public_key(&ek).unwrap();
        users_keys.push((ek.clone(), vk.clone()));
        print_hex(ek, "ek");
        print_hex(vk, "vk");

        println!("[C <- S] Sent ek_{:} to Client {:}", i, i);
    }

    // Round 1
    println!("1. Round 1");
    print!("[C] ");
    let mut n_i:Vec<u8> = get_random_key32();
    print_hex(n_i.clone(), "n_i");
    let (comm, open) = comm(&mut n_i);
    print_hex(comm.clone(), "comm");
    print_hex(open.clone(), "open");
    println!("[S <- C] Sent m_1=(init, comm) to Server");

    // Round 2
    println!("2. Round 2");
    let kemalg = kem::Kem::new(kem::Algorithm::Kyber512).unwrap();
    let (pk, sk) = kemalg.keypair().unwrap();
    print!("[S] ");
    print_hex(pk.into_vec(), "pk*");
    print!("[S] ");
    print_hex(sk.into_vec(), "sk*");
    let n_s: Vec<u8> = get_random_key32();
    let r: Vec<u8> = get_random_key32();
    print!("[S] ");
    print_hex(n_s.clone(), "n_S");
    print!("[S] ");
    print_hex(r.clone(), "r");
    for i in 0..users {
        let (ek, _) = users_keys.get(i as usize).unwrap();
        let pi = vrf.prove(ek, &r).unwrap();
        let y = vrf.proof_to_hash(&pi).unwrap();
        println!("[S] Computing VRF.Eval for client {:}", i);
        print!("[S] ");
        print_hex(pi.clone(), "pi");
        print!("[S] ");
        print_hex(y.clone(), "y");
        let c: Vec<u8> = xor(y, n_s.clone()); 
        println!("[S] Ciphertext for client {:}", i);
        print!("[S] ");
        print_hex(c.clone(), "c");

        // TODO: Sign and send m2 to client

    }



}
