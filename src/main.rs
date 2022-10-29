use sha3::{Digest, Sha3_256};
use vrf::openssl::{CipherSuite, ECVRF};
use vrf::VRF;
//use vrf::VRF;

use rand::thread_rng;
use rand::Rng;

use oqs::{kem, sig};

//use aes_gcm::{
//    aead::{Aead, KeyInit, OsRng},
//    Aes256Gcm,
//    Nonce, // Or `Aes128Gcm`
//};

fn get_random_key32() -> Vec<u8> {
    let mut x = vec![0; 32];
    thread_rng()
        .try_fill(&mut x[..])
        .expect("Error while generating random number!");
    x
}

fn print_hex(arr: &Vec<u8>, name: &str) {
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
    (commitment, open)
}

fn xor(x: &[u8], y: &[u8]) -> Vec<u8> {
    let z: Vec<_> = x.iter().zip(y).map(|(a, b)| a ^ b).collect();
    z
}

fn concat_message(
    proofs_and_ciphertexts: &Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    r: &Vec<u8>,
    pk: &Vec<u8>,
) -> Vec<u8> {
    let mut c_i: Vec<u8> = Vec::new();
    let mut pi_i: Vec<u8> = Vec::new();

    for (_, pi, c) in proofs_and_ciphertexts {
        pi_i.append(&mut pi.clone());
        c_i.append(&mut c.clone());
    }

    c_i.append(&mut pi_i);
    c_i.append(&mut r.to_owned());
    c_i.append(&mut pk.to_owned());
    c_i
}

fn set_m2(
    proofs_and_ciphertexts: &Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    signature: sig::Signature,
    r: &[u8],
    pk: &[u8],
) -> (sig::Signature, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut c_i: Vec<u8> = Vec::new();
    let mut pi_i: Vec<u8> = Vec::new();

    for (_, pi, c) in proofs_and_ciphertexts {
        pi_i.append(&mut pi.clone());
        c_i.append(&mut c.clone());
    }

    (signature, c_i, pi_i, r.to_vec(), pk.to_vec())
}

fn to_verify(c_i: &Vec<u8>, pi_i: &Vec<u8>, r: &Vec<u8>, pk: &Vec<u8>) -> Vec<u8> {
    let mut res: Vec<u8> = Vec::new();

    res.append(&mut c_i.to_owned());
    res.append(&mut pi_i.to_owned());
    res.append(&mut r.to_owned());
    res.append(&mut pk.to_owned());
    res
}

fn main() {
    // 0. Registration
    println!("0. Registration");
    let users: u16 = 10;

    let mut users_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    // Init VRF - Not Post Quantum with this library
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();

    // Init PQ signature scheme
    let sigalg = sig::Sig::new(sig::Algorithm::Dilithium2).unwrap();
    let (pk_s, sk_s) = sigalg.keypair().unwrap();
    print!("[S] ");
    print_hex(&pk_s.clone().into_vec(), "pk_S");
    print!("[S] ");
    print_hex(&sk_s.clone().into_vec(), "sk_S");

    for i in 0..users {
        println!("User {:}", i);
        let ek = get_random_key32();
        let vk = vrf.derive_public_key(&ek).unwrap();
        users_keys.push((ek.clone(), vk.clone()));
        print_hex(&ek, "ek");
        print_hex(&vk, "vk");

        println!("[C <- S] Sent ek_{:} to Client {:}", i, i);
    }

    // Round 1
    println!("1. Round 1");
    print!("[C] ");
    let mut n_i: Vec<u8> = get_random_key32();
    print_hex(&n_i, "n_i");
    let (comm, open) = comm(&mut n_i);
    print_hex(&comm, "comm");
    print_hex(&open, "open");
    println!("[S <- C] Sent m_1=(init, comm) to Server");

    // Round 2
    println!("2. Round 2");
    let kemalg = kem::Kem::new(kem::Algorithm::Kyber512).unwrap();
    let (pk, sk) = kemalg.keypair().unwrap();
    print!("[S] ");
    print_hex(&pk.clone().into_vec(), "pk*");
    print!("[S] ");
    print_hex(&sk.into_vec(), "sk*");
    let n_s: Vec<u8> = get_random_key32();
    let r: Vec<u8> = get_random_key32();
    print!("[S] ");
    print_hex(&n_s, "n_S");
    print!("[S] ");
    print_hex(&r, "r");
    let mut proofs_and_ciphertexts: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> =
        Vec::with_capacity(users as usize);
    for i in 0..users {
        let (ek, _) = users_keys.get(i as usize).unwrap();
        let pi = vrf.prove(ek, &r).unwrap();
        let y = vrf.proof_to_hash(&pi).unwrap();
        let c: Vec<u8> = xor(&y, &n_s);
        proofs_and_ciphertexts.push((y.clone(), pi.clone(), c.clone()));
        println!("[S] Computing VRF.Eval for client {:}", i);
        print!("[S] ");
        print_hex(&pi, "pi");
        print!("[S] ");
        print_hex(&y, "y");
        println!("[S] Ciphertext for client {:}", i);
        print!("[S] ");
        print_hex(&c, "c");
    }

    let mut messages2 = Vec::with_capacity(users as usize);
    for i in 0..users {
        let to_sign: Vec<u8> = concat_message(&proofs_and_ciphertexts, &r, &pk.clone().into_vec());

        let signature = sigalg.sign(&to_sign, &sk_s).unwrap();
        print!("[S] ");
        print_hex(&signature.clone().into_vec(), "signature");

        let m2 = set_m2(
            &proofs_and_ciphertexts,
            signature.clone(),
            &r,
            &pk.clone().into_vec(),
        );
        messages2.push(m2);
        println!(
            "[S -> C] Sent m_2=(signature, {{c_i}}, {{pi_i}}, r, pk*) to Client {}",
            i
        );
    }

    println!("3. Round 3");
    for i in 0..users {
        let (signature, c_i, pi_i, r, pk) = messages2.get(i as usize).unwrap();
        let to_verify: Vec<u8> = to_verify(c_i, pi_i, r, &pk.clone().to_vec());

        let verification = sigalg.verify(&to_verify, signature, &pk_s).is_ok();
        if verification {
            println!("Verification OK!");
        } else {
            println!("Verification failed!");
        }
    }
}
