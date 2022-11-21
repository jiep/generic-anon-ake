use std::time::Duration;

use aes_gcm::aes::cipher::generic_array::{
    typenum::{UInt, UTerm, B0, B1},
    GenericArray,
};

use itertools::Itertools;
use lb_vrf::poly32::Poly32;
use lb_vrf::VRF;
use lb_vrf::{
    lbvrf::{Proof, LBVRF},
    poly256::Poly256,
};
use oqs::sig::{self, Signature};

use crate::protocol::commitment::{comm, comm_vfy};
use crate::protocol::pke::{pke_dec, pke_enc};
use crate::protocol::utils::{get_random_key32, get_random_key88, xor};

use crate::protocol::client::Client;
use crate::protocol::config::Config;
use crate::protocol::server::Server;
use crate::protocol::vrf::{vrf_keypair, vrf_serialize_y_from_proof};

use super::vrf::vrf_serialize_pi;

pub type CiphertextType = (oqs::kem::Ciphertext, Vec<u8>, TagType);
pub type TagType = GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>;
pub type M2Message = ((Vec<Vec<u8>>, Vec<u8>, oqs::kem::PublicKey), Signature);

pub fn registration(clients: &mut Vec<Client>, server: &mut Server, config: &Config) {
    let mut keys: Vec<(lb_vrf::keypair::PublicKey, lb_vrf::keypair::SecretKey)> = Vec::new();
    let seed = config.get_seed();
    let param = config.get_param();

    let (pks, _) = server.get_sig_keypair();

    for _ in 0..clients.len() {
        let (vk, ek) = vrf_keypair(&seed, &param);
        keys.push((vk, ek));
    }

    for (i, client) in clients.iter_mut().enumerate() {
        let (vk, ek) = keys.get(i).unwrap();
        client.set_ek(*ek);
        server.add_key((*vk, *ek));
        client.set_pks(pks.clone());
        let vks = keys.iter().map(|x| x.0).collect();
        client.set_vks(vks);
    }
}

pub fn round_1(client: &mut Client) -> (Vec<u8>, u32) {
    let ni: Vec<u8> = get_random_key88();
    client.set_ni(&ni);
    let (comm, open) = comm(&ni);
    client.set_commitment((comm.clone(), open));

    (comm, client.get_id())
}

pub fn round_2(server: &mut Server, config: &Config, id: u32) -> M2Message {
    let (pk, sk) = config.get_kem_algorithm().keypair().unwrap();
    server.set_kem_keypair((pk.clone(), sk), id);
    let users = config.get_users_number();
    let seed = config.get_seed();
    let param = config.get_param();
    let n_s: Vec<u8> = get_random_key88();
    server.set_ns(id, n_s.clone());
    let (_, sk_s) = server.get_sig_keypair();
    let r: Vec<u8> = get_random_key32();
    let client_keys: Vec<(lb_vrf::keypair::PublicKey, lb_vrf::keypair::SecretKey)> =
        server.get_clients_keys();

    let mut proofs: Vec<Proof> = Vec::new();
    let mut yis: Vec<Vec<u8>> = Vec::new();
    let mut cis: Vec<Vec<u8>> = Vec::new();

    for i in 0..users {
        let (ek, vk) = client_keys.get(i as usize).unwrap();
        let proof = <LBVRF as VRF>::prove(r.clone(), param, *ek, *vk, seed).unwrap();

        let y: Vec<u8> = vrf_serialize_y_from_proof(&proof);
        let c = xor(&y, &n_s);

        proofs.push(proof);
        yis.push(y);
        cis.push(c);
    }

    server.add_proofs_and_ciphertexts(&cis, &yis, &proofs);

    let to_sign: Vec<u8> = [
        cis.clone().into_iter().flatten().collect(),
        r.clone(),
        pk.clone().into_vec(),
    ]
    .concat();

    let signature2: sig::Signature = config
        .get_signature_algorithm()
        .sign(&to_sign, &sk_s)
        .unwrap();

    let m2 = (cis, r, pk);

    (m2, signature2)
}

pub fn round_3(client: &mut Client, config: &Config, verbose: bool) -> (Vec<u8>, u32) {
    let (cis, r, pk, signature2) = client.get_m2_info();
    let id = client.get_id();
    let param = config.get_param();
    let seed = config.get_seed();
    let pk_s: sig::PublicKey = client.get_pks();
    client.set_pk(pk.clone());

    let to_verify: Vec<u8> = [
        cis.clone().into_iter().flatten().collect(),
        r.clone(),
        pk.into_vec(),
    ]
    .concat();

    let verification = config
        .get_signature_algorithm()
        .verify(&to_verify, &signature2, &pk_s)
        .is_ok();
    if verification {
        if verbose {
            println!("[C] Signature verification -> OK");
        }
    } else if verbose {
        println!("[C] Signature verification -> FAIL");
    }

    let ci: Vec<u8> = cis.get(id as usize).unwrap().to_vec();
    let eki: lb_vrf::keypair::SecretKey = client.get_ek();

    let vks: Vec<lb_vrf::keypair::PublicKey> = client.get_vks();
    let vki: lb_vrf::keypair::PublicKey = *vks.get(id as usize).unwrap();

    let proof_client = <LBVRF as VRF>::prove(r, param, vki, eki, seed).unwrap();
    let mut y_client: Vec<u8> = Vec::new();
    lb_vrf::serde::Serdes::serialize(&proof_client.v, &mut y_client).unwrap();
    let ns = xor(&y_client, &ci);

    client.set_ns(&ns);

    let (comm_s, open_s) = comm(&ns);
    client.set_commitment_server((comm_s.clone(), open_s));

    (comm_s, client.get_id())
}

pub fn round_4(server: &mut Server, config: &Config) -> (Vec<([Poly256; 9], Poly256)>, Signature) {
    let proofs = server.get_proofs();
    let (_, sk_s) = server.get_sig_keypair();

    let pis = proofs.iter().map(|x| (x.z, x.c)).collect_vec();

    let to_sign = concat_proofs(&proofs);

    let signature4: sig::Signature = config
        .get_signature_algorithm()
        .sign(&to_sign, &sk_s)
        .unwrap();

    (pis, signature4)
}

pub fn round_5(
    client: &mut Client,
    config: &Config,
    verbose: bool,
) -> (CiphertextType, (Vec<u8>, Vec<u8>)) {
    let kemalg = config.get_kem_algorithm();
    let users = config.get_users_number();
    let param = config.get_param();
    let seed = config.get_seed();
    let id = client.get_id();
    let cis = client.get_cis();
    let ci: Vec<u8> = cis.get(id as usize).unwrap().to_vec();
    let eki: lb_vrf::keypair::SecretKey = client.get_ek();
    let vks: Vec<lb_vrf::keypair::PublicKey> = client.get_vks();
    let vki: lb_vrf::keypair::PublicKey = *vks.get(id as usize).unwrap();
    let r: Vec<u8> = client.get_r();
    let ni: Vec<u8> = client.get_ni();
    let proofs = client.get_proofs();
    let pk_s: sig::PublicKey = client.get_pks();
    let signature4 = client.get_signature4();

    let to_verify = concat_serialized_proofs(&proofs);

    let verification = config
        .get_signature_algorithm()
        .verify(&to_verify, &signature4, &pk_s)
        .is_ok();
    if verification {
        if verbose {
            println!("[C] Signature verification -> OK");
        }
    } else if verbose {
        println!("[C] Signature verification -> FAIL");
    }

    let proof_client = <LBVRF as VRF>::prove(r.clone(), param, vki, eki, seed).unwrap();
    let mut y_client: Vec<u8> = Vec::new();
    lb_vrf::serde::Serdes::serialize(&proof_client.v, &mut y_client).unwrap();
    let ns = xor(&y_client, &ci);
    let pk = client.get_pk();

    let k: Vec<u8> = xor(&ns, &ni);

    for j in 0..users {
        let cj: Vec<u8> = cis.get(j as usize).unwrap().to_vec();
        let vkj: lb_vrf::keypair::PublicKey = *vks.get(j as usize).unwrap();
        let yj = xor(&ns, &cj);
        let (z, c) = proofs.get(j as usize).unwrap();

        let v: Poly32 = lb_vrf::serde::Serdes::deserialize(&mut yj[..].as_ref()).unwrap();

        let created_proof: Proof = Proof { v, z: *z, c: *c };

        let res = <LBVRF as VRF>::verify(r.clone(), param, vkj, created_proof).unwrap();

        if res.is_some() {
            if verbose {
                println!("[C] VRF verification for j={} -> OK", j);
            }
        } else if verbose {
            println!("[C] VRF verification for j={} -> FAIL", j);
        }
    }

    client.set_k(k);
    let (_, open) = client.get_commitment();
    let (_, open_s) = client.get_commitment_server();
    let (r, x) = open;

    let ctxi = pke_enc(kemalg, &pk, &[r, x].concat());

    (ctxi, open_s)
}

pub fn round_6(server: &mut Server, config: &Config, i: u32, verbose: bool) {
    let kemalg = config.get_kem_algorithm();
    let comms = server.get_comms();
    let comms_server = server.get_comms_server();
    let opens_server = server.get_opens_server();
    let ctxis = server.get_ctxis();
    let (_, sk) = server.get_kem_keypair(i);
    let (ct, ciphertext, iv) = ctxis.get(&i).unwrap();

    let open_i_concat: Vec<u8> = pke_dec(kemalg, sk, ct, ciphertext, iv);
    let ni: Vec<u8> = open_i_concat[0..88].to_vec();
    let ri: Vec<u8> = open_i_concat[88..].to_vec();
    let comm_i = comms.get(&i).unwrap();

    let comm_s = comms_server.get(&i).unwrap();
    let open_s = opens_server.get(&i).unwrap();

    let ns = server.get_ns(i);

    let k: Vec<u8> = xor(&ns, &ni);

    let verification1 = comm_vfy(comm_i, &(ni, ri));
    let verification2 = comm_vfy(comm_s, open_s);

    if verification1 && verification2 {
        if verbose {
            println!("[S] Commitment verification -> OK");
        }
    } else if verbose {
        println!("[S] Commitment verification -> FAIL");
    }

    server.set_k(k, i);
}

pub fn get_m1_length(m1: &(Vec<u8>, u32)) -> usize {
    m1.0.len()
}

pub fn get_m2_length(m2: &M2Message) -> usize {
    m2.0 .0.len() * m2.0 .0[0].len() + m2.0 .1.len() + m2.0 .2.len() + m2.1.len()
}

pub fn get_m3_length(m3: &(Vec<u8>, u32)) -> usize {
    get_m1_length(m3)
}

pub fn get_m4_length(m4: &(Vec<([Poly256; 9], Poly256)>, Signature)) -> usize {
    let x = vrf_serialize_pi(m4.0[0].0, m4.0[0].1);
    m4.0.len() * (x.0.len() * 9 + x.1.len()) + m4.1.len()
}

pub fn get_m5_length(m5: &(CiphertextType, (Vec<u8>, Vec<u8>))) -> usize {
    m5.0 .0.len() + m5.0 .1.len() + m5.0 .2.len() + m5.1 .0.len() + m5.1 .1.len()
}

pub fn show_diagram(times: &[Duration], lengths: &[usize], clients: u32) {
    let diagram = format!(
        r#"
                 Client i                     Server
                    |                            |
                    |                            | <---    Registration 
                    |                            |         for {clients} clients
                    |                            |         ({registration:0>3} ms)
Round 1        ---> |                            |
({round1:0>8} µs)       |                            |
                    |                            |
                    |-------------m1------------>|
                    |        ({m1:0>7} B)         |
                    |                            | <---    Round 2
                    |                            |         ({round2:0>8} ms)
                    |                            |
                    |<------------m2-------------|
                    |        ({m2:0>7} B)         |
Round 3        ---> |                            |
({round3:0>8} ms)       |                            |
                    |                            |
                    |-------------m3------------>|
                    |        ({m3:0>7} B)         |   
                    |                            | <---    Round 4
                    |                            |         ({round4:0>8} ms)
                    |                            |
                    |<------------m4-------------|
                    |        ({m4:0>7} B)         |
Round 5        ---> |                            |
({round5:0>8} ms)       |                            |
                    |                            |
                    |-------------m5------------>|
                    |        ({m5:0>7} B)         |   
                    |                            | <---    Round 6
                    |                            |         ({round6:0>8} µs)
                    |                            |

"#,
        clients = clients,
        registration = times[0].as_millis(),
        round1 = times[1].as_micros(),
        round2 = times[2].as_millis(),
        round3 = times[3].as_millis(),
        round4 = times[4].as_millis(),
        round5 = times[5].as_millis(),
        round6 = times[6].as_micros(),
        m1 = lengths[0],
        m2 = lengths[1],
        m3 = lengths[2],
        m4 = lengths[3],
        m5 = lengths[4]
    );
    println!("{}", diagram);
}

fn concat_proofs(proofs: &Vec<Proof>) -> Vec<u8> {
    let mut pis: Vec<u8> = Vec::new();

    for proof in proofs {
        let (z, c) = vrf_serialize_pi(proof.z, proof.c);
        let mut concat_pi = [
            z.as_ref().get(0).unwrap().to_vec(),
            z.as_ref().get(1).unwrap().to_vec(),
            z.as_ref().get(2).unwrap().to_vec(),
            z.as_ref().get(3).unwrap().to_vec(),
            z.as_ref().get(4).unwrap().to_vec(),
            z.as_ref().get(5).unwrap().to_vec(),
            z.as_ref().get(6).unwrap().to_vec(),
            z.as_ref().get(7).unwrap().to_vec(),
            z.as_ref().get(8).unwrap().to_vec(),
            c,
        ]
        .concat();
        pis.append(&mut concat_pi);
    }

    pis
}

fn concat_serialized_proofs(proofs: &Vec<([Poly256; 9], Poly256)>) -> Vec<u8> {
    let mut pis: Vec<u8> = Vec::new();

    for (z, c) in proofs {
        let (z, c) = vrf_serialize_pi(*z, *c);
        let mut concat_pi = [
            z.as_ref().get(0).unwrap().to_vec(),
            z.as_ref().get(1).unwrap().to_vec(),
            z.as_ref().get(2).unwrap().to_vec(),
            z.as_ref().get(3).unwrap().to_vec(),
            z.as_ref().get(4).unwrap().to_vec(),
            z.as_ref().get(5).unwrap().to_vec(),
            z.as_ref().get(6).unwrap().to_vec(),
            z.as_ref().get(7).unwrap().to_vec(),
            z.as_ref().get(8).unwrap().to_vec(),
            c,
        ]
        .concat();
        pis.append(&mut concat_pi);
    }

    pis
}
