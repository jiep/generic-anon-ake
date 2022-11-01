use itertools::izip;
use lb_vrf::lbvrf::{Proof, LBVRF};
use lb_vrf::VRF;
use oqs::{kem, sig};

use crate::commitment::{comm, comm_vfy};
use crate::pke::pke_dec;
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

    println!("keys: {}", keys.len());

    // Fix: iterate as enumerate and remove i
    let mut i = 0;
    for client in clients {
        let (vk, ek) = keys.get(i).unwrap();
        client.set_ek(ek.clone());
        server.add_key((vk.clone(), ek.clone()));
        client.set_pks(pks.clone());
        let vks = keys.iter().map(|x| x.0).collect();
        client.set_vks(vks);
        i += 1;
    }
}

pub fn round_1(client: &mut Client) {
    let mut ni: Vec<u8> = get_random_key88();
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
    Vec<(Vec<u8>, [Vec<u8>; 9])>,
    Vec<u8>,
    kem::PublicKey,
) {
    let (pk, _) = server.get_kem_keypair();
    let (_, sk_s) = server.get_sig_keypair();
    let users = config.get_users_number();
    let seed = config.get_seed();
    let param = config.get_param();
    let n_s: Vec<u8> = get_random_key88();
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

    let pis: Vec<(Vec<u8>, [Vec<u8>; 9])> = proofs.iter().map(|x| vrf_serialize_pi(x)).collect();
    (signature, cis, pis, r, pk)
}

// pub fn round_3(client: &mut Client, config: &mut Config, server: &Server) {
//     let (signature, cis, pi, r, pk) = client.get_m2_info();
//     let to_verify: Vec<u8> = to_verify(&cis, &pi, &r, &pk.into_vec());

//     let pk__: sig::PublicKey = server.get_sig_pk();

//     // TODO: Fix None after get_pks(). Remove server
//     /* let pk_s: sig::PublicKey = client.get_pks(); */
//     let verification = config
//         .get_signature_algorithm()
//         .verify(&to_verify, &signature, &pk__)
//         .is_ok();
//     if verification {
//         println!("Verification OK!");
//     } else {
//         println!("Verification failed!");
//     }

//     let ci: Vec<u8> = client
//         .get_cis()
//         .get(client.get_id() as usize)
//         .unwrap()
//         .to_vec();
//     let eki: lb_vrf::keypair::SecretKey = client.get_ek();
//     let r: Vec<u8> = client.get_r();
//     let ni: Vec<u8> = client.get_ni();

//     println!("eki: {:?}", eki);
//     println!("r: {:?}", r);
//     println!("ni: {:?}", ni);

//     // let pi = config.get_vrf().prove(&eki, &r).unwrap();
//     // let y = config.get_vrf().proof_to_hash(&pi).unwrap();
//     // let ns: Vec<u8> = xor(&y, &ci);

//     // TODO: execute VRF.Verify for all j in C\{i}

//     // let k: Vec<u8> = xor(&ns, &ni);
//     // client.set_k(k);
// }

// pub fn round_4(server: &mut Server, config: &mut Config, i: u8) {
//     let kemalg = config.get_kem_algorithm();
//     let cnis = server.get_cnis();
//     let comms = server.get_comms();
//     let opens = server.get_opens();
//     let (ct, ciphertext, iv) = cnis.get(&i).unwrap();
//     let comm = comms.get(&i).unwrap();
//     let open = opens.get(&i).unwrap();
//     let (_, sk) = server.get_kem_keypair();
//     let ns = server.get_ns();

//     let mut ni: Vec<u8> = pke_dec(kemalg, sk, ct, ciphertext, iv);

//     let k: Vec<u8> = xor(&ns, &ni);

//     comm_vfy(comm, open, &mut ni);

//     server.set_k(k);
// }

fn concat_message(cis: &Vec<Vec<u8>>, proofs: &Vec<Proof>, r: &Vec<u8>, pk: &Vec<u8>) -> Vec<u8> {
    let mut c_i: Vec<u8> = Vec::new();
    let mut pi_i: Vec<u8> = Vec::new();

    for (proof, ct) in izip!(proofs, cis) {
        let (z, c) = vrf_serialize_pi(&proof);
        let mut concat_pi = [
            z,
            c.as_ref().get(0).unwrap().to_vec(),
            c.as_ref().get(1).unwrap().to_vec(),
            c.as_ref().get(2).unwrap().to_vec(),
            c.as_ref().get(3).unwrap().to_vec(),
            c.as_ref().get(4).unwrap().to_vec(),
            c.as_ref().get(5).unwrap().to_vec(),
            c.as_ref().get(6).unwrap().to_vec(),
            c.as_ref().get(7).unwrap().to_vec(),
            c.as_ref().get(8).unwrap().to_vec(),
            c.as_ref().get(8).unwrap().to_vec(),
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

// fn to_verify(cis: &Vec<Vec<u8>>, proofs: &Vec<Vec<u8>>, r: &Vec<u8>, pk: &Vec<u8>) -> Vec<u8> {
//     let mut res: Vec<u8> = Vec::new();
//     let mut c_i: Vec<u8> = Vec::new();
//     let mut pi_i: Vec<u8> = Vec::new();

//     for (pi, c) in izip!(proofs, cis) {
//         pi_i.append(&mut pi.clone());
//         c_i.append(&mut c.clone());
//     }

//     res.append(&mut c_i.to_owned());
//     res.append(&mut pi_i.to_owned());
//     res.append(&mut r.to_owned());
//     res.append(&mut pk.to_owned());
//     res
// }
