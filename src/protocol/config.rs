use lb_vrf::param::Param;
use oqs::{kem, sig};

pub struct Config {
    users_numbers: u32,
    seed: [u8; 32],
    param: Param,
    kem: kem::Kem,
    sig: sig::Sig,
}

impl Config {
    pub fn new(
        users_numbers: u32,
        seed: [u8; 32],
        param: Param,
        kem: kem::Kem,
        sig: sig::Sig,
    ) -> Self {
        Config {
            users_numbers,
            seed,
            param,
            kem,
            sig,
        }
    }

    pub fn get_seed(&self) -> [u8; 32] {
        self.seed
    }

    pub fn get_param(&self) -> Param {
        self.param
    }

    pub fn get_kem_algorithm(&self) -> &kem::Kem {
        &self.kem
    }

    pub fn get_users_number(&self) -> u32 {
        self.users_numbers
    }

    pub fn get_signature_algorithm(&self) -> &sig::Sig {
        &self.sig
    }
}
