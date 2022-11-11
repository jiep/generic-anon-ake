use lb_vrf::param::Param;
use oqs::kem;

pub struct Config {
    users_numbers: u8,
    seed: [u8; 32],
    param: Param,
    kem: kem::Kem,
}

impl Config {
    pub fn new(
        users_numbers: u8,
        seed: [u8; 32],
        param: Param,
        kem: kem::Kem,
    ) -> Self {
        Config {
            users_numbers,
            seed,
            param,
            kem,
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

    pub fn get_users_number(&self) -> u8 {
        self.users_numbers
    }
}
