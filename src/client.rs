use aes_gcm::aes::cipher::generic_array::{
    typenum::{UInt, UTerm, B0, B1},
    GenericArray,
};
use lb_vrf::keypair::{PublicKey, SecretKey};
use oqs::{
    kem::{self, Ciphertext},
    sig,
};

use crate::server::Server;

#[derive(Debug)]
pub struct Client {
    id: u8,
    ek: Option<SecretKey>,
    ni: Vec<u8>,
    vks: Vec<PublicKey>,
    //commitment and open
    commitment: (Vec<u8>, Vec<u8>),
    signature: Option<sig::Signature>,
    cis: Vec<Vec<u8>>,
    proofs: Vec<([Vec<u8>; 9], Vec<u8>)>,
    r: Vec<u8>,
    pk: Option<kem::PublicKey>,
    pk_s: Option<sig::PublicKey>,
    k: Vec<u8>,
}

impl Client {
    pub fn new(id: u8) -> Self {
        Client {
            id,
            ek: None,
            ni: Vec::new(),
            vks: Vec::new(),
            commitment: (Vec::new(), Vec::new()),
            signature: None,
            cis: Vec::new(),
            proofs: Vec::new(),
            r: Vec::new(),
            pk: None,
            pk_s: None,
            k: Vec::new(),
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

    pub fn set_commitment(&mut self, commitment: (Vec<u8>, Vec<u8>)) {
        self.commitment = commitment;
    }

    pub fn set_pks(&mut self, pk_s: sig::PublicKey) {
        self.pk_s = Some(pk_s);
    }

    pub fn set_k(&mut self, k: Vec<u8>) {
        self.k = k;
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

    pub fn get_ni(&self) -> Vec<u8> {
        self.ni.clone()
    }

    pub fn get_r(&self) -> Vec<u8> {
        self.r.clone()
    }

    pub fn get_cis(&self) -> Vec<Vec<u8>> {
        self.cis.clone()
    }

    pub fn get_pks(&self) -> sig::PublicKey {
        self.pk_s.as_ref().unwrap().clone()
    }

    pub fn get_commitment(&self) -> (Vec<u8>, Vec<u8>) {
        self.commitment.clone()
    }

    pub fn get_vks(&self) -> Vec<PublicKey> {
        self.vks.clone()
    }

    pub fn get_id(&self) -> u8 {
        self.id
    }

    pub fn send_m1(&self, server: &mut Server) {
        let (comm, _) = self.get_commitment();
        let m1 = ("init", comm, self.get_id());

        server.receive_m1(m1);
    }

    #[allow(clippy::type_complexity)]
    pub fn send_m3(
        &self,
        m3: (
            Vec<u8>,
            (
                Ciphertext,
                Vec<u8>,
                GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
            ),
        ),
        server: &mut Server,
    ) {
        let (open, cni) = m3;
        server.receive_m3((open, cni, self.get_id()));
    }

    #[allow(clippy::type_complexity)]
    pub fn receive_m2(
        &mut self,
        m2: (
            sig::Signature,
            Vec<Vec<u8>>,
            Vec<([Vec<u8>; 9], Vec<u8>)>,
            Vec<u8>,
            kem::PublicKey,
        ),
    ) {
        let (signature, cis, proofs, r, pk) = m2;
        self.signature = Some(signature);
        self.cis = cis;
        self.proofs = proofs;
        self.r = r;
        self.pk = Some(pk);
    }

    #[allow(clippy::type_complexity)]
    pub fn get_m2_info(
        &self,
    ) -> (
        sig::Signature,
        Vec<Vec<u8>>,
        Vec<([Vec<u8>; 9], Vec<u8>)>,
        Vec<u8>,
        kem::PublicKey,
    ) {
        (
            self.signature.as_ref().unwrap().clone(),
            self.cis.clone(),
            self.proofs.clone(),
            self.r.clone(),
            self.pk.as_ref().unwrap().clone(),
        )
    }

    //pub fn new(id:u8, ek: Vec<u8>, vks: Vec<Vec<u8>>) -> Self {
    //    Client { id, ek, vks }
    //}
}

impl Clone for Client {
    fn clone(&self) -> Client {
        Client {
            id: self.id,
            ek: self.ek,
            ni: self.ni.clone(),
            vks: self.vks.clone(),
            commitment: self.commitment.clone(),
            signature: self.signature.clone(),
            cis: self.cis.clone(),
            proofs: self.proofs.clone(),
            r: self.r.clone(),
            pk: self.pk.clone(),
            pk_s: self.pk_s.clone(),
            k: self.k.clone(),
        }
    }
}
