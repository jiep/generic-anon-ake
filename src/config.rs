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
            vrf: vrf,
            kem,
            sig,
        }
    }

    pub fn get_vrf(&mut self) -> &mut ECVRF {
        &mut self.vrf
    }
}
