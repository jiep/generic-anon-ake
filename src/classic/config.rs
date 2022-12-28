pub struct Config {
    users_numbers: u32,
}

impl Config {
    pub fn new(users_numbers: u32) -> Self {
        Config { users_numbers }
    }

    pub fn get_users_number(&self) -> u32 {
        self.users_numbers
    }
}
