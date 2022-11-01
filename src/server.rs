use std::collections::HashMap;

use lb_vrf::lbvrf::Proof;
use oqs::{
    kem::{self, Ciphertext},
    sig,
};

use aes_gcm::aes::cipher::generic_array::{
    typenum::{UInt, UTerm, B0, B1},
    GenericArray,
};

use crate::client::Client;
use crate::config::Config;

#[derive(Debug)]
pub struct Server {
    clients_keys: Vec<(lb_vrf::keypair::PublicKey, lb_vrf::keypair::SecretKey)>,
    signature_keys: (sig::PublicKey, sig::SecretKey),
    kem_keys: (kem::PublicKey, kem::SecretKey),
    comms: HashMap<u8, Vec<u8>>,
    opens: HashMap<u8, Vec<u8>>,
    cis: Vec<Vec<u8>>,
    yis: Vec<Vec<u8>>,
    proofs: Vec<Proof>,
    ns: Vec<u8>,
    #[allow(clippy::type_complexity)]
    cnis: HashMap<
        u8,
        (
            Ciphertext,
            Vec<u8>,
            GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
        ),
    >,
    k: Vec<u8>,
}

impl Server {
    /* pub fn new(clients_keys: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        Server { clients_keys }
    } */

    pub fn new(config: &mut Config) -> Self {
        let (pk_sig, sk_sig) = config.get_signature_algorithm().keypair().unwrap();
        let (pk_kem, sk_kem) = config.get_kem_algorithm().keypair().unwrap(); // TODO: change to round 2

        Server {
            clients_keys: Vec::new(),
            signature_keys: (pk_sig, sk_sig),
            kem_keys: (pk_kem, sk_kem),
            comms: HashMap::new(),
            opens: HashMap::new(),
            cis: Vec::new(),
            yis: Vec::new(),
            proofs: Vec::new(),
            ns: Vec::new(),
            cnis: HashMap::new(),
            k: Vec::new(),
        }
    }

    pub fn receive_m1(&mut self, m1: (&str, Vec<u8>, u8)) {
        let (_, comm, id) = m1;

        self.add_commitment(comm, id);
    }

    fn add_commitment(&mut self, comm: Vec<u8>, id: u8) {
        self.comms.insert(id, comm);
    }

    fn add_open(&mut self, open: Vec<u8>, id: u8) {
        self.opens.insert(id, open);
    }

    #[allow(clippy::type_complexity)]
    fn add_cni(
        &mut self,
        cni: (
            Ciphertext,
            Vec<u8>,
            GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
        ),
        id: u8,
    ) {
        self.cnis.insert(id, cni);
    }

    pub fn get_kem_keypair(&self) -> (kem::PublicKey, kem::SecretKey) {
        self.kem_keys.clone()
    }

    pub fn get_sig_keypair(&self) -> (sig::PublicKey, sig::SecretKey) {
        self.signature_keys.clone()
    }

    pub fn get_sig_pk(&self) -> sig::PublicKey {
        self.signature_keys.0.clone()
    }

    pub fn add_key(&mut self, key: (lb_vrf::keypair::PublicKey, lb_vrf::keypair::SecretKey)) {
        self.clients_keys.push(key);
    }

    pub fn get_clients_keys(&self) -> Vec<(lb_vrf::keypair::PublicKey, lb_vrf::keypair::SecretKey)> {
        self.clients_keys.clone()
    }

    #[allow(clippy::type_complexity)]
    pub fn get_cnis(
        &self,
    ) -> HashMap<
        u8,
        (
            Ciphertext,
            Vec<u8>,
            GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
        ),
    > {
        self.cnis.clone()
    }

    pub fn get_comms(&self) -> HashMap<u8, Vec<u8>> {
        self.comms.clone()
    }

    pub fn get_opens(&self) -> HashMap<u8, Vec<u8>> {
        self.opens.clone()
    }

    pub fn set_ns(&mut self, ns: Vec<u8>) {
        self.ns = ns;
    }

    pub fn set_k(&mut self, k: Vec<u8>) {
        self.k = k;
    }

    pub fn get_ns(&self) -> Vec<u8> {
        self.ns.clone()
    }

    pub fn add_proofs_and_ciphertexts(
        &mut self,
        cis: &[Vec<u8>],
        yis: &[Vec<u8>],
        proofs: &Vec<Proof>,
    ) {
        self.cis = cis.to_owned();
        self.yis = yis.to_owned();
        self.proofs = proofs.to_vec();
    }

    pub fn get_proofs(&self) -> Vec<Proof> {
        self.proofs.clone()
    }

    pub fn get_cis(&self) -> Vec<Vec<u8>> {
        self.cis.clone()
    }

    #[allow(clippy::type_complexity)]
    pub fn send_m2(
        &self,
        m2: (
            sig::Signature,
            Vec<Vec<u8>>,
            Vec<Vec<u8>>,
            Vec<u8>,
            kem::PublicKey,
        ),
        client: &mut Client,
    ) {
        client.receive_m2(m2);
    }

    #[allow(clippy::type_complexity)]
    pub fn receive_m3(
        &mut self,
        m3: (
            Vec<u8>,
            (
                Ciphertext,
                Vec<u8>,
                GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
            ),
            u8,
        ),
    ) {
        let (open, cni, id) = m3;
        self.add_open(open, id);
        self.add_cni(cni, id);
    }
}