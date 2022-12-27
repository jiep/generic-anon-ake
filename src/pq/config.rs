use oqs::{kem, sig};

pub struct Config {
    users_numbers: u32,
    kem: kem::Kem,
    sig: sig::Sig,
}

impl Config {
    pub fn new(users_numbers: u32, kem: kem::Kem, sig: sig::Sig) -> Self {
        Config {
            users_numbers,
            kem,
            sig,
        }
    }

    pub fn get_kem_algorithm(&self) -> &kem::Kem {
        &self.kem
    }

    pub fn get_signature_algorithm(&self) -> &sig::Sig {
        &self.sig
    }

    pub fn get_users_number(&self) -> u32 {
        self.users_numbers
    }
}
