use lb_vrf::keypair::{PublicKey, SecretKey};
use oqs::kem;
use sha3::{Digest, Sha3_256};

use crate::protocol::server::Server;

use super::protocol::CiphertextType;

#[derive(Debug)]
pub struct Client {
    id: u32,
    ek: Option<SecretKey>,
    ni: Vec<u8>,
    vks: Vec<PublicKey>,
    //commitment and open
    commitment: (Vec<u8>, (Vec<u8>, Vec<u8>)),
    commitment_server: (Vec<u8>, (Vec<u8>, Vec<u8>)),
    cis: Vec<Vec<u8>>,
    proofs: Vec<([Vec<u8>; 9], Vec<u8>)>,
    r: Vec<u8>,
    pk: Option<kem::PublicKey>,
    k: Vec<u8>,
    ns: Vec<u8>,
}

impl Client {
    pub fn new(id: u32) -> Self {
        Client {
            id,
            ek: None,
            ni: Vec::new(),
            vks: Vec::new(),
            commitment: (Vec::new(), (Vec::new(), Vec::new())),
            commitment_server: (Vec::new(), (Vec::new(), Vec::new())),
            cis: Vec::new(),
            proofs: Vec::new(),
            r: Vec::new(),
            pk: None,
            k: Vec::new(),
            ns: Vec::new(),
        }
    }

    pub fn set_ek(&mut self, ek: lb_vrf::keypair::SecretKey) {
        self.ek = Some(ek);
    }

    pub fn set_vks(&mut self, vks: Vec<lb_vrf::keypair::PublicKey>) {
        self.vks = vks;
    }

    pub fn set_ni(&mut self, ni: &[u8]) {
        self.ni = ni.to_owned();
    }

    pub fn set_ns(&mut self, ns: &[u8]) {
        self.ns = ns.to_owned();
    }

    pub fn set_commitment(&mut self, commitment: (Vec<u8>, (Vec<u8>, Vec<u8>))) {
        self.commitment = commitment;
    }

    pub fn set_commitment_server(&mut self, commitment: (Vec<u8>, (Vec<u8>, Vec<u8>))) {
        self.commitment_server = commitment;
    }

    pub fn set_k(&mut self, k: Vec<u8>) {
        let mut hasher = Sha3_256::new();
        hasher.update(k);
        let hashed_k: Vec<u8> = hasher.finalize().to_vec();
        self.k = hashed_k;
    }

    pub fn get_ek(&self) -> SecretKey {
        self.ek.unwrap()
    }

    pub fn get_key(&self) -> Vec<u8> {
        self.k.clone()
    }

    pub fn get_pk(&self) -> kem::PublicKey {
        self.pk.as_ref().unwrap().clone()
    }

    pub fn set_pk(&mut self, pk: kem::PublicKey) {
        self.pk = Some(pk);
    }

    pub fn get_ni(&self) -> Vec<u8> {
        self.ni.clone()
    }

    pub fn get_ns(&self) -> Vec<u8> {
        self.ns.clone()
    }

    pub fn get_r(&self) -> Vec<u8> {
        self.r.clone()
    }

    pub fn get_cis(&self) -> Vec<Vec<u8>> {
        self.cis.clone()
    }

    pub fn get_commitment(&self) -> (Vec<u8>, (Vec<u8>, Vec<u8>)) {
        self.commitment.clone()
    }

    pub fn get_commitment_server(&self) -> (Vec<u8>, (Vec<u8>, Vec<u8>)) {
        self.commitment_server.clone()
    }

    pub fn get_vks(&self) -> Vec<PublicKey> {
        self.vks.clone()
    }

    pub fn get_id(&self) -> u32 {
        self.id
    }

    pub fn send_m1(&self, m1: (Vec<u8>, u32), server: &mut Server) {
        server.receive_m1(m1);
    }

    pub fn send_m3(&self, m3: (Vec<u8>, u32), server: &mut Server) {
        let (comm_s, _) = m3;

        server.receive_m3((comm_s, self.get_id()));
    }

    pub fn send_m5(&self, m5: (CiphertextType, (Vec<u8>, Vec<u8>)), server: &mut Server) {
        let (ctxi, open_s) = m5;

        server.receive_m5((ctxi, open_s, self.get_id()));
    }

    pub fn receive_m2(&mut self, m2: (Vec<Vec<u8>>, Vec<u8>, kem::PublicKey)) {
        let (cis, r, pk) = m2;
        self.cis = cis;
        self.r = r;
        self.pk = Some(pk);
    }

    pub fn get_m2_info(&self) -> (Vec<Vec<u8>>, Vec<u8>, kem::PublicKey) {
        (
            self.cis.clone(),
            self.r.clone(),
            self.pk.as_ref().unwrap().clone(),
        )
    }

    pub fn receive_m4(&mut self, m4: Vec<([Vec<u8>; 9], Vec<u8>)>) {
        let proofs = m4;
        self.proofs = proofs;
    }
}

impl Clone for Client {
    fn clone(&self) -> Client {
        Client {
            id: self.id,
            ek: self.ek,
            ni: self.ni.clone(),
            vks: self.vks.clone(),
            commitment: self.commitment.clone(),
            commitment_server: self.commitment_server.clone(),
            cis: self.cis.clone(),
            proofs: self.proofs.clone(),
            r: self.r.clone(),
            pk: self.pk.clone(),
            k: self.k.clone(),
            ns: self.ni.clone(),
        }
    }
}
