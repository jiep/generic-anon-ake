use std::collections::HashMap;

use lb_vrf::{lbvrf::Proof, poly256::Poly256};
use oqs::{
    kem::{self, Ciphertext},
    sig::{self, Signature},
};

use sha3::{Digest, Sha3_256};

use crate::protocol::client::Client;

use super::{
    config::Config,
    protocol::{CiphertextType, M2Message, TagType},
};

#[derive(Debug)]
pub struct Server {
    clients_keys: Vec<(lb_vrf::keypair::PublicKey, lb_vrf::keypair::SecretKey)>,
    kem_keys: HashMap<u32, (kem::PublicKey, kem::SecretKey)>,
    comms: HashMap<u32, Vec<u8>>,
    comms_server: HashMap<u32, Vec<u8>>,
    opens_server: HashMap<u32, (Vec<u8>, Vec<u8>)>,
    cis: Vec<Vec<u8>>,
    yis: Vec<Vec<u8>>,
    proofs: Vec<Proof>,
    ns: HashMap<u32, Vec<u8>>,
    k: HashMap<u32, Vec<u8>>,
    ctxis: HashMap<u32, CiphertextType>,
    signature_keys: (sig::PublicKey, sig::SecretKey),
}

impl Server {
    pub fn new(config: &Config) -> Self {
        let (pk_sig, sk_sig) = config.get_signature_algorithm().keypair().unwrap();

        Server {
            clients_keys: Vec::new(),
            kem_keys: HashMap::new(),
            comms: HashMap::new(),
            comms_server: HashMap::new(),
            opens_server: HashMap::new(),
            cis: Vec::new(),
            yis: Vec::new(),
            proofs: Vec::new(),
            ns: HashMap::new(),
            k: HashMap::new(),
            ctxis: HashMap::new(),
            signature_keys: (pk_sig, sk_sig),
        }
    }

    pub fn receive_m1(&mut self, m1: (Vec<u8>, u32)) {
        let (comm, id) = m1;

        self.add_commitment(comm, id);
    }

    fn add_commitment(&mut self, comm: Vec<u8>, id: u32) {
        self.comms.insert(id, comm);
    }

    fn add_commitment_server(&mut self, comm: Vec<u8>, id: u32) {
        self.comms_server.insert(id, comm);
    }

    fn add_open_server(&mut self, open: (Vec<u8>, Vec<u8>), id: u32) {
        self.opens_server.insert(id, open);
    }

    pub fn get_kem_keypair(&self, index: u32) -> (kem::PublicKey, kem::SecretKey) {
        self.kem_keys.get(&index).unwrap().clone()
    }

    pub fn set_kem_keypair(&mut self, keys: (kem::PublicKey, kem::SecretKey), index: u32) {
        self.kem_keys.insert(index, keys);
    }

    pub fn add_key(&mut self, key: (lb_vrf::keypair::PublicKey, lb_vrf::keypair::SecretKey)) {
        self.clients_keys.push(key);
    }

    pub fn get_clients_keys(
        &self,
    ) -> Vec<(lb_vrf::keypair::PublicKey, lb_vrf::keypair::SecretKey)> {
        self.clients_keys.clone()
    }

    pub fn get_ctxis(&self) -> HashMap<u32, (Ciphertext, Vec<u8>, TagType)> {
        self.ctxis.clone()
    }

    pub fn get_comms(&self) -> HashMap<u32, Vec<u8>> {
        self.comms.clone()
    }

    pub fn get_comms_server(&self) -> HashMap<u32, Vec<u8>> {
        self.comms_server.clone()
    }

    pub fn get_opens_server(&self) -> HashMap<u32, (Vec<u8>, Vec<u8>)> {
        self.opens_server.clone()
    }

    pub fn set_ns(&mut self, index: u32, ns: Vec<u8>) {
        self.ns.insert(index, ns);
    }

    fn set_ctxi(&mut self, ctxi: CiphertextType, id: u32) {
        self.ctxis.insert(id, ctxi);
    }

    pub fn set_k(&mut self, key: Vec<u8>, index: u32) {
        let mut hasher = Sha3_256::new();
        hasher.update(key);
        let hashed_k: Vec<u8> = hasher.finalize().to_vec();
        self.k.insert(index, hashed_k);
    }

    pub fn get_key(&mut self, index: u32) -> Vec<u8> {
        self.k.get(&index).unwrap().to_vec()
    }

    pub fn get_ns(&self, index: u32) -> Vec<u8> {
        self.ns.get(&index).unwrap().clone()
    }

    pub fn get_sig_keypair(&self) -> (sig::PublicKey, sig::SecretKey) {
        self.signature_keys.clone()
    }

    pub fn get_sig_pk(&self) -> sig::PublicKey {
        self.signature_keys.0.clone()
    }

    pub fn add_proofs_and_ciphertexts(
        &mut self,
        cis: &[Vec<u8>],
        yis: &[Vec<u8>],
        proofs: &Vec<Proof>,
    ) {
        self.cis = cis.to_owned();
        self.yis = yis.to_owned();
        self.proofs = proofs.to_owned();
    }

    pub fn get_proofs(&self) -> Vec<Proof> {
        self.proofs.clone()
    }

    pub fn get_cis(&self) -> Vec<Vec<u8>> {
        self.cis.clone()
    }

    pub fn send_m2(&self, m2: M2Message, client: &mut Client) {
        client.receive_m2(m2);
    }

    pub fn receive_m3(&mut self, m3: (Vec<u8>, u32)) {
        let (comm_s, id) = m3;
        self.add_commitment_server(comm_s, id);
    }

    pub fn send_m4(&self, m4: (Vec<([Poly256; 9], Poly256)>, Signature), client: &mut Client) {
        client.receive_m4(m4);
    }

    pub fn receive_m5(&mut self, m5: (CiphertextType, (Vec<u8>, Vec<u8>), u32)) {
        let (ctxi, open_s, id) = m5;
        self.add_open_server(open_s, id);
        self.set_ctxi(ctxi, id);
    }
}
