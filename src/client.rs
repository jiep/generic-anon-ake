pub struct Client {
    id: u8,
    ek: Vec<u8>,
    vks: Vec<Vec<u8>>,
}

impl Client {
    pub fn new(id: u8) -> Self {
        Client {
            id,
            ek: Vec::new(),
            vks: Vec::new(),
        }
    }

    pub fn set_ek(&mut self, ek: Vec<u8>) {
        self.ek = ek;
    }

    pub fn set_vks(&mut self, vks: Vec<Vec<u8>>) {
        self.vks = vks;
    }

    pub fn get_ek(&self) -> Vec<u8> {
        self.ek.clone()
    }

    //pub fn new(id:u8, ek: Vec<u8>, vks: Vec<Vec<u8>>) -> Self {
    //    Client { id, ek, vks }
    //}
}
