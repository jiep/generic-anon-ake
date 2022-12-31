use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::{
    classic::{
        ccapke::ccapke_gen,
        commitment::{comm, comm_vfy},
        pke::{pke_dec, pke_enc, pke_gen},
        sig::{sig_sign, sig_vry},
    },
    common::{prf::prf, utils::get_random_key32},
};

use super::{
    ccapke::{ccapke_dec, ccapke_enc},
    client::Client,
    config::Config,
    pke::check_ciphertext,
    server::Server,
};

pub type M2Message = (
    (Vec<Vec<u8>>, Vec<u8>, pke_ecies::PublicKey),
    k256::ecdsa::Signature,
);

pub fn registration(config: &Config) -> (Server, Client) {
    let mut keys: Vec<(pke_ecies::PublicKey, pke_ecies::SecretKey)> = Vec::new();
    let clients = config.get_users_number();
    let mut server: Server = Server::new();
    let mut client: Client = Client::new(0);

    let (pks, _) = server.get_sig_keypair();
    client.set_pks(pks);

    for _ in 0..clients {
        let (vk, ek) = pke_gen();
        keys.push((vk, ek));
    }

    let (_, ek) = keys.get(0_usize).unwrap();
    client.set_ek(ek.to_owned());

    for (vk, ek) in keys.iter() {
        server.add_key((vk.to_owned(), ek.to_owned()));
    }

    let vks: Vec<pke_ecies::PublicKey> = keys.iter().map(|x| x.0.to_owned()).collect();
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
    let (pk, sk) = ccapke_gen();
    server.set_ecies_keypair((pk, sk), id);
    let users = config.get_users_number();
    let n_s: Vec<u8> = get_random_key32();
    server.set_ns(id, n_s.clone());
    let (_, sk_s) = server.get_sig_keypair();
    let r: Vec<u8> = get_random_key32();
    let client_keys: Vec<(pke_ecies::PublicKey, pke_ecies::SecretKey)> = server.get_clients_keys();

    let mut cis: Vec<Vec<u8>> = Vec::new();

    for i in 0..users {
        let (ek, _) = client_keys.get(i as usize).unwrap();
        let nonce = (i as u128).to_be_bytes();
        let ri = prf(&r, &nonce);
        let c = pke_enc(ek, &n_s, &ri);
        cis.push(c);
    }

    server.add_proofs_and_ciphertexts(&cis, &r);

    let to_sign: Vec<u8> = [
        cis.clone().into_iter().flatten().collect(),
        r.clone(),
        pk.serialize().into(),
    ]
    .concat();

    let signature2 = sig_sign(&sk_s.into(), &to_sign);

    let m2 = (cis, r, pk);

    (m2, signature2)
}

pub fn round_3(client: &mut Client, verbose: bool) -> (Vec<u8>, u32) {
    let (cis, r, pk, signature2) = client.get_m2_info();
    let id = client.get_id();
    let pk_s: k256::PublicKey = client.get_pks();
    client.set_pk(pk);

    let to_verify: Vec<u8> = [
        cis.clone().into_iter().flatten().collect(),
        r,
        pk.serialize().into(),
    ]
    .concat();

    let verification = sig_vry(&pk_s.into(), &to_verify, &signature2);

    if verification {
        if verbose {
            println!("[C] Signature verification -> OK");
        }
    } else if verbose {
        println!("[C] Signature verification -> KO");
    }

    let ct = cis.get(id as usize).unwrap();
    let eki: pke_ecies::SecretKey = client.get_ek();

    let ns = pke_dec(&eki, ct);

    client.set_ns(&ns);

    let (comm_s, open_s) = comm(&ns);
    client.set_commitment_server((comm_s.clone(), open_s));

    (comm_s, client.get_id())
}

pub fn round_4(server: &mut Server) -> (Vec<u8>, k256::ecdsa::Signature) {
    let r = server.get_r();
    let (_, sk_s) = server.get_sig_keypair();

    let signature4 = sig_sign(&sk_s.into(), &r);

    (r, signature4)
}

pub fn round_5(
    client: &mut Client,
    config: &Config,
    verbose: bool,
) -> (Vec<u8>, (Vec<u8>, Vec<u8>)) {
    let users = config.get_users_number();
    let cis = client.get_cis();
    let vks: Vec<pke_ecies::PublicKey> = client.get_vks();
    let r: Vec<u8> = client.get_r();
    let ni: Vec<u8> = client.get_ni();
    let ns: Vec<u8> = client.get_ns();
    let pk_s: k256::PublicKey = client.get_pks();
    let signature4 = client.get_signature4();

    let verification = sig_vry(&pk_s.into(), &r, &signature4);

    if verification {
        if verbose {
            println!("[C] Signature verification -> OK");
        }
    } else if verbose {
        println!("[C] Signature verification -> KO");
    }

    let pk = client.get_pk();

    for j in 0..users {
        let cj = cis.get(j as usize).unwrap();
        let vkj = vks.get(j as usize).unwrap();

        let nonce = (j as u128).to_be_bytes();
        let rj = prf(&r, &nonce);
        let ci_check = pke_enc(vkj, &ns, &rj);

        if check_ciphertext(&ci_check, cj) {
            if verbose {
                println!("[C] Ciphertext verification for j={} -> OK", j);
            }
        } else if verbose {
            println!("[C] Ciphertext verification for j={} -> KO", j);
        }
    }

    let mut hasher = Sha256::new();
    hasher.update([ns, ni].concat());
    let k: Vec<u8> = hasher.finalize().to_vec();
    client.set_k(k);
    client.set_sid(client.get_key());

    let (_, open) = client.get_commitment();
    let (_, open_s) = client.get_commitment_server();
    let (r, x) = open;

    let ctxi = ccapke_enc(&pk, &[r, x].concat());

    (ctxi, open_s)
}

pub fn round_6(server: &mut Server, i: u32, verbose: bool) {
    let comms = server.get_comms();
    let comms_server = server.get_comms_server();
    let opens_server = server.get_opens_server();
    let ctxis = server.get_ctxis();
    let (_, sk) = server.get_ecies_keypair(i);
    let ct = ctxis.get(&i).unwrap();

    let open_i_concat: Vec<u8> = ccapke_dec(&sk, ct);
    let ni: Vec<u8> = open_i_concat[0..32].to_vec();
    let ri: Vec<u8> = open_i_concat[32..].to_vec();
    let comm_i = comms.get(&i).unwrap();

    let comm_s = comms_server.get(&i).unwrap();
    let open_s = opens_server.get(&i).unwrap();

    let ns = server.get_ns(i);

    let mut hasher = Sha256::new();
    hasher.update([ns, ni.clone()].concat());
    let k: Vec<u8> = hasher.finalize().to_vec();

    let verification1 = comm_vfy(comm_i, &(ni, ri));
    let verification2 = comm_vfy(comm_s, open_s);

    if verification1 && verification2 {
        if verbose {
            println!("[S] Commitment verification -> OK");
        }
    } else if verbose {
        println!("[S] Commitment verification -> KO");
    }

    server.set_k(k, i);
    let hashed_k = server.get_key(i);
    server.set_sid(hashed_k, i);
}

pub fn get_m1_length(m1: &(Vec<u8>, u32)) -> usize {
    m1.0.len()
}

pub fn get_m2_length(m2: &M2Message) -> usize {
    m2.0 .0.len() * m2.0 .0[0].len()
        + m2.0 .1.len()
        + m2.0 .2.serialize().len()
        + m2.1.to_vec().len()
}

pub fn get_m3_length(m3: &(Vec<u8>, u32)) -> usize {
    get_m1_length(m3)
}

pub fn get_m4_length(m4: &(Vec<u8>, k256::ecdsa::Signature)) -> usize {
    m4.0.len() + m4.1.to_vec().len()
}

pub fn get_m5_length(m5: &(Vec<u8>, (Vec<u8>, Vec<u8>))) -> usize {
    m5.0.len() + m5.1 .0.len() + m5.1 .1.len()
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
