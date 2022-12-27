use oqs::{
    kem,
    sig::{self, Signature},
};
use sha3::{Digest, Sha3_256};

use crate::{
    common::server::Server,
    pq::protocol::{CiphertextType, M2Message},
};

#[derive(Debug)]
pub struct Client {
    id: u32,
    ek: Option<kem::SecretKey>,
    ni: Vec<u8>,
    vks: Vec<kem::PublicKey>,
    //commitment and open
    commitment: (Vec<u8>, (Vec<u8>, Vec<u8>)),
    commitment_server: (Vec<u8>, (Vec<u8>, Vec<u8>)),
    cis: Vec<CiphertextType>,
    ri: Vec<u8>,
    r: Vec<u8>,
    pk: Option<kem::PublicKey>,
    k: Vec<u8>,
    ns: Vec<u8>,
    signature2: Option<sig::Signature>,
    signature4: Option<sig::Signature>,
    pk_s: Option<sig::PublicKey>,
    sid: Vec<u8>,
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
            ri: Vec::new(),
            r: Vec::new(),
            pk: None,
            k: Vec::new(),
            ns: Vec::new(),
            signature2: None,
            signature4: None,
            pk_s: None,
            sid: Vec::new(),
        }
    }

    pub fn set_ek(&mut self, ek: kem::SecretKey) {
        self.ek = Some(ek);
    }

    pub fn set_vks(&mut self, vks: Vec<kem::PublicKey>) {
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

    pub fn set_sid(&mut self, k: Vec<u8>) {
        let mut hasher = Sha3_256::new();
        hasher.update(k);
        let hashed_sid: Vec<u8> = hasher.finalize().to_vec();
        self.sid = hashed_sid;
    }

    pub fn get_ek(&self) -> kem::SecretKey {
        self.ek.as_ref().unwrap().clone()
    }

    pub fn get_sid(&self) -> Vec<u8> {
        self.sid.clone()
    }

    pub fn get_signature4(&self) -> Signature {
        self.signature4.as_ref().unwrap().clone()
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

    pub fn set_pks(&mut self, pk_s: sig::PublicKey) {
        self.pk_s = Some(pk_s);
    }

    pub fn get_pks(&self) -> sig::PublicKey {
        self.pk_s.as_ref().unwrap().clone()
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

    pub fn get_cis(&self) -> Vec<CiphertextType> {
        self.cis.clone()
    }

    pub fn get_ri(&self) -> Vec<u8> {
        self.ri.clone()
    }

    pub fn get_commitment(&self) -> (Vec<u8>, (Vec<u8>, Vec<u8>)) {
        self.commitment.clone()
    }

    pub fn get_commitment_server(&self) -> (Vec<u8>, (Vec<u8>, Vec<u8>)) {
        self.commitment_server.clone()
    }

    pub fn get_vks(&self) -> Vec<kem::PublicKey> {
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

    pub fn receive_m2(&mut self, m2: M2Message) {
        let ((cis, r, pk), signature2) = m2;
        self.cis = cis;
        self.r = r;
        self.pk = Some(pk);
        self.signature2 = Some(signature2);
    }

    pub fn get_m2_info(&self) -> (Vec<CiphertextType>, Vec<u8>, oqs::kem::PublicKey, Signature) {
        (
            self.cis.clone(),
            self.r.clone(),
            self.pk.as_ref().unwrap().clone(),
            self.signature2.as_ref().unwrap().clone(),
        )
    }

    pub fn receive_m4(&mut self, m4: (Vec<u8>, Signature)) {
        let (r, signature4) = m4;
        self.r = r;
        self.signature4 = Some(signature4);
    }
}

impl Clone for Client {
    fn clone(&self) -> Client {
        Client {
            id: self.id,
            ek: self.ek.clone(),
            ni: self.ni.clone(),
            vks: self.vks.clone(),
            commitment: self.commitment.clone(),
            commitment_server: self.commitment_server.clone(),
            cis: self.cis.clone(),
            ri: self.ri.clone(),
            r: self.r.clone(),
            pk: self.pk.clone(),
            k: self.k.clone(),
            ns: self.ni.clone(),
            signature2: self.signature2.clone(),
            signature4: self.signature4.clone(),
            pk_s: self.pk_s.clone(),
            sid: self.sid.clone(),
        }
    }
}
