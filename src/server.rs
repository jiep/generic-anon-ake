use std::collections::HashMap;

use oqs::{kem, sig};

use crate::config::Config;

pub struct Server {
    clients_keys: Vec<(Vec<u8>, Vec<u8>)>,
    signature_keys: (sig::PublicKey, sig::SecretKey),
    kem_keys: (kem::PublicKey, kem::SecretKey),
    comms: HashMap<u8, Vec<u8>>,
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
        }
    }

    pub fn receive_m1(&mut self, m1: (&str, Vec<u8>, u8)) {
        let (_, comm, id) = m1;

        self.add_commitment(comm, id);
    }

    fn add_commitment(&mut self, comm: Vec<u8>, id: u8) {
        self.comms.insert(id, comm);
    }

    pub fn add_key(&mut self, key: (Vec<u8>, Vec<u8>)) {
        self.clients_keys.push(key);
    }
}
