use sha2::{Digest, Sha256};

use super::{protocol::M2Message, server::Server};

#[derive(Debug)]
pub struct Client {
    id: u32,
    ek: Option<ecies::SecretKey>,
    ni: Vec<u8>,
    vks: Vec<ecies::PublicKey>,
    //commitment and open
    commitment: (Vec<u8>, (Vec<u8>, Vec<u8>)),
    commitment_server: (Vec<u8>, (Vec<u8>, Vec<u8>)),
    cis: Vec<Vec<u8>>,
    ri: Vec<u8>,
    r: Vec<u8>,
    pk: Option<ecies::PublicKey>,
    k: Vec<u8>,
    ns: Vec<u8>,
    signature2: Option<k256::ecdsa::Signature>,
    signature4: Option<k256::ecdsa::Signature>,
    pk_s: Option<k256::PublicKey>,
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

    pub fn set_ek(&mut self, ek: ecies::SecretKey) {
        self.ek = Some(ek);
    }

    pub fn set_vks(&mut self, vks: Vec<ecies::PublicKey>) {
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
        let mut hasher = Sha256::new();
        hasher.update(k);
        let hashed_k: Vec<u8> = hasher.finalize().to_vec();
        self.k = hashed_k;
    }

    pub fn set_sid(&mut self, k: Vec<u8>) {
        let mut hasher = Sha256::new();
        hasher.update(k);
        let hashed_sid: Vec<u8> = hasher.finalize().to_vec();
        self.sid = hashed_sid;
    }

    pub fn get_ek(&self) -> ecies::SecretKey {
        self.ek.unwrap()
    }

    pub fn get_sid(&self) -> Vec<u8> {
        self.sid.clone()
    }

    pub fn get_signature4(&self) -> k256::ecdsa::Signature {
        self.signature4.unwrap()
    }

    pub fn get_key(&self) -> Vec<u8> {
        self.k.clone()
    }

    pub fn get_pk(&self) -> ecies::PublicKey {
        self.pk.unwrap()
    }

    pub fn set_pk(&mut self, pk: ecies::PublicKey) {
        self.pk = Some(pk);
    }

    pub fn set_pks(&mut self, pk_s: k256::PublicKey) {
        self.pk_s = Some(pk_s);
    }

    pub fn get_pks(&self) -> k256::PublicKey {
        self.pk_s.unwrap()
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

    pub fn get_ri(&self) -> Vec<u8> {
        self.ri.clone()
    }

    pub fn get_commitment(&self) -> (Vec<u8>, (Vec<u8>, Vec<u8>)) {
        self.commitment.clone()
    }

    pub fn get_commitment_server(&self) -> (Vec<u8>, (Vec<u8>, Vec<u8>)) {
        self.commitment_server.clone()
    }

    pub fn get_vks(&self) -> Vec<ecies::PublicKey> {
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

    pub fn send_m5(&self, m5: (Vec<u8>, (Vec<u8>, Vec<u8>)), server: &mut Server) {
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

    pub fn get_m2_info(
        &self,
    ) -> (
        Vec<Vec<u8>>,
        Vec<u8>,
        ecies::PublicKey,
        k256::ecdsa::Signature,
    ) {
        (
            self.cis.clone(),
            self.r.clone(),
            self.pk.unwrap(),
            self.signature2.unwrap(),
        )
    }

    pub fn receive_m4(&mut self, m4: (Vec<u8>, k256::ecdsa::Signature)) {
        let (r, signature4) = m4;
        self.r = r;
        self.signature4 = Some(signature4);
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
            ri: self.ri.clone(),
            r: self.r.clone(),
            pk: self.pk,
            k: self.k.clone(),
            ns: self.ni.clone(),
            signature2: self.signature2,
            signature4: self.signature4,
            pk_s: self.pk_s,
            sid: self.sid.clone(),
        }
    }
}
