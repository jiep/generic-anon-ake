use aes_gcm::aes::cipher::generic_array::{
    typenum::{UInt, UTerm, B0, B1},
    GenericArray,
};
use itertools::izip;
use lb_vrf::lbvrf::{Proof, LBVRF};
use lb_vrf::poly32::Poly32;
use lb_vrf::VRF;
use oqs::kem::Ciphertext;
use oqs::{kem, sig};

use crate::commitment::{comm, comm_vfy};
use crate::pke::{pke_dec, pke_enc};
use crate::utils::{get_random_key32, get_random_key88, xor};

use crate::client::Client;
use crate::config::Config;
use crate::server::Server;
use crate::vrf::{vrf_keypair, vrf_serialize_pi, vrf_serialize_y_from_proof};

pub fn registration(clients: Vec<&mut Client>, server: &mut Server, config: &mut Config) {
    let mut keys: Vec<(lb_vrf::keypair::PublicKey, lb_vrf::keypair::SecretKey)> = Vec::new();
    let seed = config.get_seed();
    let param = config.get_param();

    let (pks, _) = server.get_sig_keypair();

    for _ in 0..clients.len() {
        let (vk, ek) = vrf_keypair(&seed, &param);
        keys.push((vk, ek));
    }

    for (i, client) in clients.into_iter().enumerate() {
        let (vk, ek) = keys.get(i).unwrap();
        client.set_ek(*ek);
        server.add_key((*vk, *ek));
        client.set_pks(pks.clone());
        let vks = keys.iter().map(|x| x.0).collect();
        client.set_vks(vks);
    }
}

pub fn round_1(client: &mut Client) {
    let ni: Vec<u8> = get_random_key88();
    client.set_ni(&ni);
    let commitment = comm(&ni);
    client.set_commitment(commitment);
}

#[allow(clippy::type_complexity)]
pub fn round_2(
    server: &mut Server,
    config: &mut Config,
) -> (
    sig::Signature,
    Vec<Vec<u8>>,
    Vec<([Vec<u8>; 9], Vec<u8>)>,
    Vec<u8>,
    kem::PublicKey,
) {
    let (pk, _) = server.get_kem_keypair();
    let (_, sk_s) = server.get_sig_keypair();
    let users = config.get_users_number();
    let seed = config.get_seed();
    let param = config.get_param();
    let n_s: Vec<u8> = get_random_key88();
    server.set_ns(n_s.clone());
    let r: Vec<u8> = get_random_key32();
    let client_keys: Vec<(lb_vrf::keypair::PublicKey, lb_vrf::keypair::SecretKey)> =
        server.get_clients_keys();

    let mut proofs: Vec<Proof> = Vec::new();
    let mut yis: Vec<Vec<u8>> = Vec::new();
    let mut cis: Vec<Vec<u8>> = Vec::new();

    for i in 0..users {
        let (ek, vk) = client_keys.get(i as usize).unwrap();
        let proof = <LBVRF as VRF>::prove(r.clone(), param, *ek, *vk, seed).unwrap();

        // println!("y: v={:?}", proof.v);
        let y: Vec<u8> = vrf_serialize_y_from_proof(&proof);
        let c = xor(&y, &n_s);

        proofs.push(proof);
        yis.push(y);

        //proof.v.serialize(&mut y).unwrap();

        //println!("y: {:?}", y);
        // println!("pi: (z={:?}, c={:?}); ", proof.z, proof.c);
        cis.push(c);
    }

    server.add_proofs_and_ciphertexts(&cis, &yis, &proofs);

    let to_sign: Vec<u8> = concat_message(&cis, &proofs, &r, &pk.clone().into_vec());

    let signature: sig::Signature = config
        .get_signature_algorithm()
        .sign(&to_sign, &sk_s)
        .unwrap();

    let pis: Vec<([Vec<u8>; 9], Vec<u8>)> =
        proofs.iter().map(|x| vrf_serialize_pi(x.z, x.c)).collect();
    (signature, cis, pis, r, pk)
}

#[allow(clippy::type_complexity)]
pub fn round_3(
    client: &mut Client,
    config: &mut Config,
) -> (
    Vec<u8>,
    (
        Ciphertext,
        Vec<u8>,
        GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
    ),
) {
    let (signature, cis, pis, r, pk) = client.get_m2_info();
    let kemalg = config.get_kem_algorithm();
    let ni: Vec<u8> = client.get_ni();
    let cni = pke_enc(kemalg, &pk, &ni);
    let to_verify: Vec<u8> = to_verify(&cis, &pis, &r, &pk.into_vec());
    let users = config.get_users_number();
    let param = config.get_param();
    let seed = config.get_seed();
    let id = client.get_id();

    let pk_s: sig::PublicKey = client.get_pks();
    let verification = config
        .get_signature_algorithm()
        .verify(&to_verify, &signature, &pk_s)
        .is_ok();
    if verification {
        println!("[C] Signature verification -> OK");
    } else {
        println!("[C] Signature verification -> FAIL");
    }

    let cis = client.get_cis();
    let ci: Vec<u8> = cis.get(id as usize).unwrap().to_vec();
    let eki: lb_vrf::keypair::SecretKey = client.get_ek();
    let vks: Vec<lb_vrf::keypair::PublicKey> = client.get_vks();
    let vki: lb_vrf::keypair::PublicKey = *vks.get(id as usize).unwrap();
    let r: Vec<u8> = client.get_r();

    // println!("eki: {:?}", eki);
    // println!("r: {:?}", r);
    // println!("ni: {:?}", ni);

    let proof_client = <LBVRF as VRF>::prove(r.clone(), param, vki, eki, seed).unwrap();
    let mut y_client: Vec<u8> = Vec::new();
    lb_vrf::serde::Serdes::serialize(&proof_client.v, &mut y_client).unwrap();
    let ns = xor(&y_client, &ci);

    let k: Vec<u8> = xor(&ns, &ni);

    for j in 0..users {
        let cj: Vec<u8> = cis.get(j as usize).unwrap().to_vec();
        let vkj: lb_vrf::keypair::PublicKey = *vks.get(j as usize).unwrap();
        let yj = xor(&ns, &cj);

        let v: Poly32 = lb_vrf::serde::Serdes::deserialize(&mut yj[..].as_ref()).unwrap();

        let created_proof: Proof = Proof {
            v,
            z: proof_client.z,
            c: proof_client.c,
        };

        let res = <LBVRF as VRF>::verify(r.clone(), param, vkj, created_proof).unwrap();
        if res.is_some() {
            println!("[C] VRF verification for j={} -> OK", j);
        } else {
            println!("[C] VRF verification for j={} -> FAIL", j);
        }
    }

    client.set_k(k);
    let (_, open) = client.get_commitment();
    (open, cni)
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

    let ni: Vec<u8> = pke_dec(kemalg, sk, ct, ciphertext, iv);

    let k: Vec<u8> = xor(&ns, &ni);

    comm_vfy(comm, open, &ni);

    server.set_k(k, i);
}

fn concat_message(cis: &Vec<Vec<u8>>, proofs: &Vec<Proof>, r: &Vec<u8>, pk: &Vec<u8>) -> Vec<u8> {
    let mut c_i: Vec<u8> = Vec::new();
    let mut pi_i: Vec<u8> = Vec::new();

    for (proof, ct) in izip!(proofs, cis) {
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
            z.as_ref().get(8).unwrap().to_vec(),
            c,
        ]
        .concat();
        pi_i.append(&mut concat_pi);
        c_i.append(&mut ct.clone());
    }

    c_i.append(&mut pi_i);
    c_i.append(&mut r.to_owned());
    c_i.append(&mut pk.to_owned());
    c_i
}

fn to_verify(
    cis: &Vec<Vec<u8>>,
    pis: &Vec<([Vec<u8>; 9], Vec<u8>)>,
    r: &Vec<u8>,
    pk: &Vec<u8>,
) -> Vec<u8> {
    let mut res: Vec<u8> = Vec::new();
    let mut c_i: Vec<u8> = Vec::new();
    let mut pi_i: Vec<u8> = Vec::new();

    for ((z, c), ct) in izip!(pis, cis) {
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
            z.as_ref().get(8).unwrap().to_vec(),
            c.to_vec(),
        ]
        .concat();
        pi_i.append(&mut concat_pi);
        c_i.append(&mut ct.clone());
    }

    res.append(&mut c_i.to_owned());
    res.append(&mut pi_i.to_owned());
    res.append(&mut r.to_owned());
    res.append(&mut pk.to_owned());
    res
}
