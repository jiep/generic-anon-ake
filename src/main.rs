use lb_vrf::lbvrf::LBVRF;
use lb_vrf::param::Param;
use lb_vrf::serde::Serdes;
use lb_vrf::VRF;
use rand::RngCore;

use oqs::*;
//use aes_gcm::{
//    aead::{Aead, KeyInit, OsRng},
//    Aes256Gcm, Nonce // Or `Aes128Gcm`
//};

fn main() {
    let mut seed = [0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut seed);

    let param: Param = <LBVRF as VRF>::paramgen(seed).unwrap();
    let (_pk, _sk) = <LBVRF as VRF>::keygen(seed, param).unwrap();
    let mut buf: Vec<u8> = vec![];
    let mut buf2: Vec<u8> = vec![];
    _pk.serialize(&mut buf).unwrap();
    println!("pk: 0x{:}", hex::encode(&buf));
    _sk.serialize(&mut buf2).unwrap();
    println!("sk: 0x{:}", hex::encode(&buf2));
    let message = "this is a message that vrf signs";
    let seed = [0u8; 32];
    let proof = <LBVRF as VRF>::prove(message, param, _pk, _sk, seed).unwrap();
    let res = <LBVRF as VRF>::verify(message, param, _pk, proof).unwrap();
    if !res.is_none() {
        println!("Ok!");
    }

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

    //let key = Aes256Gcm::generate_key(&mut OsRng);
    //let cipher = Aes256Gcm::new(&key);
    //let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
    //let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())?;
    //let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
    //assert_eq!(&plaintext, b"plaintext message");
    //Ok(())
}
