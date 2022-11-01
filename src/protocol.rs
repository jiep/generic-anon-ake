use itertools::izip;
use oqs::{kem, sig};
// use vrf::VRF;

use crate::commitment::{comm, comm_vfy};
use crate::pke::pke_dec;
use crate::utils::{get_random_key32, xor};

use crate::client::Client;
use crate::config::Config;
use crate::server::Server;

pub fn registration(clients: &mut Vec<Client>, server: &mut Server, config: &mut Config) {
    let mut vks: Vec<Vec<u8>> = Vec::new();
    let (pks, _) = server.get_sig_keypair();

    for client in clients {
        let ek = get_random_key32();
        // let vk = config.get_vrf().derive_public_key(&ek).unwrap();
        // vks.push(vk.clone());
        client.set_ek(ek.to_owned());
        // server.add_key((ek, vk));
        client.set_pks(pks.clone());
        //client.set_vks(vks.clone());
    }
}

pub fn round_1(client: &mut Client) {
    let mut ni: Vec<u8> = get_random_key32();
    let commitment = comm(&mut ni);
    client.set_ni(ni);
    client.set_commitment(commitment);
}

#[allow(clippy::type_complexity)]
pub fn round_2(
    server: &mut Server,
    config: &mut Config,
) -> (
    sig::Signature,
    Vec<Vec<u8>>,
    Vec<Vec<u8>>,
    Vec<u8>,
    kem::PublicKey,
) {
    let (pk, _) = server.get_kem_keypair();
    let (_, sk_s) = server.get_sig_keypair();
    let users = config.get_users_number();
    let n_s: Vec<u8> = get_random_key32();
    let r: Vec<u8> = get_random_key32();
    let client_keys = server.get_clients_keys();

    let mut proofs: Vec<Vec<u8>> = Vec::new();
    let mut yis: Vec<Vec<u8>> = Vec::new();
    let mut cis: Vec<Vec<u8>> = Vec::new();
    for i in 0..users {
        let (ek, _) = client_keys.get(i as usize).unwrap();
        // let pi: Vec<u8> = config.get_vrf().prove(ek, &r).unwrap();
        // let y: Vec<u8> = config.get_vrf().proof_to_hash(&pi).unwrap();
        // let c: Vec<u8> = xor(&y, &n_s);

        // proofs.push(pi);
        // yis.push(y);
        // cis.push(c);
    }

    server.add_proofs_and_ciphertexts(&cis, &yis, &proofs);

    let to_sign: Vec<u8> = concat_message(&cis, &proofs, &r, &pk.clone().into_vec());

    let signature: sig::Signature = config
        .get_signature_algorithm()
        .sign(&to_sign, &sk_s)
        .unwrap();

    (signature, cis, proofs, r, pk)
}

pub fn round_3(client: &mut Client, config: &mut Config, server: &Server) {
    let (signature, cis, pi, r, pk) = client.get_m2_info();
    let to_verify: Vec<u8> = to_verify(&cis, &pi, &r, &pk.into_vec());

    let pk__: sig::PublicKey = server.get_sig_pk();

    // TODO: Fix None after get_pks(). Remove server
    /* let pk_s: sig::PublicKey = client.get_pks(); */

    let verification = config
        .get_signature_algorithm()
        .verify(&to_verify, &signature, &pk__)
        .is_ok();
    if verification {
        println!("Verification OK!");
    } else {
        println!("Verification failed!");
    }

    let ci: Vec<u8> = client
        .get_cis()
        .get(client.get_id() as usize)
        .unwrap()
        .to_vec();
    let eki: Vec<u8> = client.get_ek();
    let r: Vec<u8> = client.get_r();
    let ni: Vec<u8> = client.get_ni();

    println!("eki: {:?}", eki);
    println!("r: {:?}", r);
    println!("ni: {:?}", ni);

    // let pi = config.get_vrf().prove(&eki, &r).unwrap();
    // let y = config.get_vrf().proof_to_hash(&pi).unwrap();
    // let ns: Vec<u8> = xor(&y, &ci);

    // TODO: execute VRF.Verify for all j in C\{i}

    // let k: Vec<u8> = xor(&ns, &ni);
    // client.set_k(k);
}

pub fn round_4(server: &mut Server, config: &mut Config, i: u8) {
    let kemalg = config.get_kem_algorithm();
    let cnis = server.get_cnis();
    let comms = server.get_comms();
    let opens = server.get_opens();
    let (ct, ciphertext, iv) = cnis.get(&i).unwrap();
    let comm = comms.get(&i).unwrap();
    let open = opens.get(&i).unwrap();
    let (_, sk) = server.get_kem_keypair();
    let ns = server.get_ns();

    let mut ni: Vec<u8> = pke_dec(kemalg, sk, ct, ciphertext, iv);

    let k: Vec<u8> = xor(&ns, &ni);

    comm_vfy(comm, open, &mut ni);

    server.set_k(k);
}

fn concat_message(cis: &Vec<Vec<u8>>, proofs: &Vec<Vec<u8>>, r: &Vec<u8>, pk: &Vec<u8>) -> Vec<u8> {
    let mut c_i: Vec<u8> = Vec::new();
    let mut pi_i: Vec<u8> = Vec::new();

    for (pi, c) in izip!(proofs, cis) {
        pi_i.append(&mut pi.clone());
        c_i.append(&mut c.clone());
    }

    c_i.append(&mut pi_i);
    c_i.append(&mut r.to_owned());
    c_i.append(&mut pk.to_owned());
    c_i
}

pub fn to_verify(cis: &Vec<Vec<u8>>, proofs: &Vec<Vec<u8>>, r: &Vec<u8>, pk: &Vec<u8>) -> Vec<u8> {
    let mut res: Vec<u8> = Vec::new();
    let mut c_i: Vec<u8> = Vec::new();
    let mut pi_i: Vec<u8> = Vec::new();

    for (pi, c) in izip!(proofs, cis) {
        pi_i.append(&mut pi.clone());
        c_i.append(&mut c.clone());
    }

    res.append(&mut c_i.to_owned());
    res.append(&mut pi_i.to_owned());
    res.append(&mut r.to_owned());
    res.append(&mut pk.to_owned());
    res
}
