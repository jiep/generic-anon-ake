use lb_vrf::param::Param;
use oqs::kem;
use qrllib::rust_wrapper::xmss_alt::{algsxmss_fast::BDSState, xmss_common::XMSSParams};

pub struct Config {
    users_numbers: u32,
    seed: [u8; 48],
    param: XMSSParams,
    kem: kem::Kem,
}

impl Config {
    pub fn new(users_numbers: u32, seed: [u8; 48], param: XMSSParams, kem: kem::Kem) -> Self {
        Config {
            users_numbers,
            seed,
            param,
            kem,
        }
    }

    pub fn get_seed(&self) -> [u8; 48] {
        self.seed
    }

    pub fn get_params(&self) -> &XMSSParams {
        &self.param
    }

    pub fn get_kem_algorithm(&self) -> &kem::Kem {
        &self.kem
    }

    pub fn get_users_number(&self) -> u32 {
        self.users_numbers
    }
}
