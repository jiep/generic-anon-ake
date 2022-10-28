use vrf::openssl::{CipherSuite, ECVRF};
use vrf::VRF;

//use rand::RngCore;

use oqs::*;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm,
    Nonce, // Or `Aes128Gcm`
};

fn main() {
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    // Inputs: Secret Key, Public Key (derived) & Message
    let secret_key =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let public_key = vrf.derive_public_key(&secret_key).unwrap();
    let message: &[u8] = b"sample";

    // VRF proof and hash output
    let pi = vrf.prove(&secret_key, message).unwrap();
    let hash = vrf.proof_to_hash(&pi).unwrap();
    println!("hash: 0x{:}", hex::encode(&hash));

    // VRF proof verification (returns VRF hash output)
    let beta = vrf.verify(&public_key, &pi, message).unwrap();
    println!("beta: 0x{:}", hex::encode(&beta));

    let sigalg = sig::Sig::new(sig::Algorithm::Dilithium2).unwrap();
    let kemalg = kem::Kem::new(kem::Algorithm::Kyber512).unwrap();
    // A's long-term secrets
    let (a_sig_pk, a_sig_sk) = sigalg.keypair().unwrap();
    // B's long-term secrets
    let (b_sig_pk, b_sig_sk) = sigalg.keypair().unwrap();

    // assumption: A has (a_sig_sk, a_sig_pk, b_sig_pk)
    // assumption: B has (b_sig_sk, b_sig_pk, a_sig_pk)

    // A -> B: kem_pk, signature
    let (kem_pk, kem_sk) = kemalg.keypair().unwrap();
    let signature = sigalg.sign(kem_pk.as_ref(), &a_sig_sk).unwrap();

    // B -> A: kem_ct, signature
    sigalg
        .verify(kem_pk.as_ref(), &signature, &a_sig_pk)
        .unwrap();
    let (kem_ct, b_kem_ss) = kemalg.encapsulate(&kem_pk).unwrap();
    let signature = sigalg.sign(kem_ct.as_ref(), &b_sig_sk).unwrap();

    // A verifies, decapsulates, now both have kem_ss
    sigalg
        .verify(kem_ct.as_ref(), &signature, &b_sig_pk)
        .unwrap();
    let a_kem_ss = kemalg.decapsulate(&kem_sk, &kem_ct).unwrap();
    assert_eq!(a_kem_ss, b_kem_ss);

    let key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
    let ciphertext = cipher
        .encrypt(nonce, b"plaintext message".as_ref())
        .unwrap();
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
    assert_eq!(&plaintext, b"plaintext message");

    //Ok(())
}
