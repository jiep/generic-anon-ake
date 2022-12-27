use std::time::Duration;

use aes_gcm::aes::cipher::generic_array::{
    typenum::{UInt, UTerm, B0, B1},
    GenericArray,
};

use oqs::{
    kem,
    sig::{self, Signature},
};
use sha3::{Digest, Sha3_256};

use crate::protocol::commitment::{comm, comm_vfy};
use crate::protocol::pke::{pke_dec, pke_enc};
use crate::protocol::utils::get_random_key32;

use crate::protocol::client::Client;
use crate::protocol::config::Config;
use crate::protocol::server::Server;

use super::prf::prf;

pub type CiphertextType = (oqs::kem::Ciphertext, Vec<u8>, TagType);
pub type TagType = GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>;
pub type M2Message = (
    (Vec<CiphertextType>, Vec<u8>, oqs::kem::PublicKey),
    Signature,
);

pub fn registration(config: &Config) -> (Server, Client) {
    let mut keys: Vec<(kem::PublicKey, kem::SecretKey)> = Vec::new();
    let clients = config.get_users_number();
    let kemalg = config.get_kem_algorithm();
    let mut server: Server = Server::new(config);
    let mut client: Client = Client::new(0);

    let (pks, _) = server.get_sig_keypair();
    client.set_pks(pks);

    for _ in 0..clients {
        let (vk, ek) = kemalg.keypair().unwrap();
        keys.push((vk, ek));
    }

    let (_, ek) = keys.get(0_usize).unwrap();
    client.set_ek(ek.to_owned());

    for (vk, ek) in keys.iter() {
        server.add_key((vk.to_owned(), ek.to_owned()));
    }

    let vks = keys.iter().map(|x| x.0.to_owned()).collect();
    client.set_vks(vks);

    (server, client)
}

pub fn round_1(client: &mut Client) -> (Vec<u8>, u32) {
    let ni: Vec<u8> = get_random_key32();
    client.set_ni(&ni);
    let (comm, open) = comm(&ni);
    client.set_commitment((comm.clone(), open));

    (comm, client.get_id())
}

pub fn round_2(server: &mut Server, config: &Config, id: u32) -> M2Message {
    let (pk, sk) = config.get_kem_algorithm().keypair().unwrap();
    let kemalg = config.get_kem_algorithm();
    server.set_kem_keypair((pk.clone(), sk), id);
    let users = config.get_users_number();
    let n_s: Vec<u8> = get_random_key32();
    server.set_ns(id, n_s.clone());
    let (_, sk_s) = server.get_sig_keypair();
    let r: Vec<u8> = get_random_key32();
    let client_keys: Vec<(kem::PublicKey, kem::SecretKey)> = server.get_clients_keys();

    let mut cis: Vec<CiphertextType> = Vec::new();

    for i in 0..users {
        let (ek, _) = client_keys.get(i as usize).unwrap();
        let nonce = (i as u128).to_be_bytes();
        // TODO: Add to PKE
        let _ri = prf(&r, &nonce);

        let c = pke_enc(kemalg, ek, &n_s);

        cis.push(c);
    }

    server.add_proofs_and_ciphertexts(&cis, &r);

    let to_sign: Vec<u8> = [
        cis.clone()
            .iter()
            .map(|x| {
                [
                    x.0.to_owned().into_vec(),
                    x.1.to_owned().to_vec(),
                    x.2.to_vec(),
                ]
                .concat()
            })
            .into_iter()
            .flatten()
            .collect(),
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
    let kemalg = config.get_kem_algorithm();
    let (cis, r, pk, signature2) = client.get_m2_info();
    let id = client.get_id();
    let pk_s: sig::PublicKey = client.get_pks();
    client.set_pk(pk.clone());

    let to_verify: Vec<u8> = [
        cis.iter()
            .map(|x| {
                [
                    x.0.to_owned().into_vec(),
                    x.1.to_owned().to_vec(),
                    x.2.to_vec(),
                ]
                .concat()
            })
            .into_iter()
            .flatten()
            .collect(),
        r,
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

    let (ct, ciphertext, tag) = cis.get(id as usize).unwrap();
    let eki: kem::SecretKey = client.get_ek();

    let ns = pke_dec(kemalg, eki, ct, ciphertext, tag);

    client.set_ns(&ns);

    let (comm_s, open_s) = comm(&ns);
    client.set_commitment_server((comm_s.clone(), open_s));

    (comm_s, client.get_id())
}

pub fn round_4(server: &mut Server, config: &Config) -> (Vec<u8>, Signature) {
    let r = server.get_r();
    let (_, sk_s) = server.get_sig_keypair();

    let signature4: sig::Signature = config.get_signature_algorithm().sign(&r, &sk_s).unwrap();

    (r, signature4)
}

pub fn round_5(
    client: &mut Client,
    config: &Config,
    verbose: bool,
) -> (CiphertextType, (Vec<u8>, Vec<u8>)) {
    let kemalg = config.get_kem_algorithm();
    let users = config.get_users_number();
    let cis = client.get_cis();
    let vks: Vec<kem::PublicKey> = client.get_vks();
    let r: Vec<u8> = client.get_r();
    let ni: Vec<u8> = client.get_ni();
    let ns: Vec<u8> = client.get_ns();
    let pk_s: sig::PublicKey = client.get_pks();
    let signature4 = client.get_signature4();

    let verification = config
        .get_signature_algorithm()
        .verify(&r, &signature4, &pk_s)
        .is_ok();
    if verification {
        if verbose {
            println!("[C] Signature verification -> OK");
        }
    } else if verbose {
        println!("[C] Signature verification -> FAIL");
    }

    let pk = client.get_pk();

    for j in 0..users {
        let _cj = cis.get(j as usize).unwrap();
        let vkj = vks.get(j as usize).unwrap();

        let nonce = (j as u128).to_be_bytes();
        // TODO: Add to PKE
        // TODO: Add assert
        let _rj = prf(&r, &nonce);
        let _ci_check = pke_enc(kemalg, vkj, &ns);

        // if res.is_some() {
        //     if verbose {
        //         println!("[C] Ciphertext verification for j={} -> OK", j);
        //     }
        // } else if verbose {
        //     println!("[C] Ciphertext verification for j={} -> FAIL", j);
        // }
    }

    let mut hasher = Sha3_256::new();
    hasher.update([ns, ni].concat());
    let k: Vec<u8> = hasher.finalize().to_vec();
    client.set_k(k);
    client.set_sid(client.get_key());

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
    let ni: Vec<u8> = open_i_concat[0..32].to_vec();
    let ri: Vec<u8> = open_i_concat[32..].to_vec();
    let comm_i = comms.get(&i).unwrap();

    let comm_s = comms_server.get(&i).unwrap();
    let open_s = opens_server.get(&i).unwrap();

    let ns = server.get_ns(i);

    let mut hasher = Sha3_256::new();
    hasher.update([ns, ni.clone()].concat());
    let k: Vec<u8> = hasher.finalize().to_vec();

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
    let hashed_k = server.get_key(i);
    server.set_sid(hashed_k, i);
}

pub fn get_m1_length(m1: &(Vec<u8>, u32)) -> usize {
    m1.0.len()
}

pub fn get_m2_length(m2: &M2Message) -> usize {
    m2.0 .0.len() * m2.0 .0[0].0.len() + m2.0 .1.len() + m2.1.len()
}

pub fn get_m3_length(m3: &(Vec<u8>, u32)) -> usize {
    get_m1_length(m3)
}

pub fn get_m4_length(m4: &(Vec<u8>, Signature)) -> usize {
    m4.0.len() + m4.1.len()
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
