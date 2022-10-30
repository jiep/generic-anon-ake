use oqs::{kem, sig};
use vrf::openssl::ECVRF;

pub struct Config {
    users_numbers: u8,
    vrf: ECVRF,
    kem: kem::Kem,
    sig: sig::Sig,
}

impl Config {
    pub fn new(users_numbers: u8, vrf: ECVRF, kem: kem::Kem, sig: sig::Sig) -> Self {
        Config {
            users_numbers,
            vrf,
            kem,
            sig,
        }
    }

    pub fn get_vrf(&mut self) -> &mut ECVRF {
        &mut self.vrf
    }

    pub fn get_signature_algorithm(&mut self) -> &mut sig::Sig {
        &mut self.sig
    }

    pub fn get_kem_algorithm(&mut self) -> &mut kem::Kem {
        &mut self.kem
    }

    pub fn get_users_number(&self) -> u8 {
        self.users_numbers
    }
}
