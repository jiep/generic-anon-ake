use crate::server::Server;

pub struct Client {
    id: u8,
    ek: Vec<u8>,
    ni: Vec<u8>,
    vks: Vec<Vec<u8>>,
    //commitment and open
    commitment: (Vec<u8>, Vec<u8>),
}

impl Client {
    pub fn new(id: u8) -> Self {
        Client {
            id,
            ek: Vec::new(),
            ni: Vec::new(),
            vks: Vec::new(),
            commitment: (Vec::new(), Vec::new()),
        }
    }

    pub fn set_ek(&mut self, ek: Vec<u8>) {
        self.ek = ek;
    }

    pub fn set_vks(&mut self, vks: Vec<Vec<u8>>) {
        self.vks = vks;
    }

    pub fn set_ni(&mut self, ni: Vec<u8>) {
        self.ni = ni;
    }

    pub fn set_commitment(&mut self, commitment: (Vec<u8>, Vec<u8>)) {
        self.commitment = commitment;
    }

    pub fn get_ek(&self) -> Vec<u8> {
        self.ek.clone()
    }

    pub fn get_commitment(&self) -> (Vec<u8>, Vec<u8>) {
        self.commitment.clone()
    }

    pub fn get_id(&self) -> u8 {
        self.id
    }

    pub fn send_m1(&self, server: &mut Server) {
        let (comm, _) = self.get_commitment();
        let m1 = ("init", comm, self.get_id());

        server.receive_m1(m1);
    }

    //pub fn new(id:u8, ek: Vec<u8>, vks: Vec<Vec<u8>>) -> Self {
    //    Client { id, ek, vks }
    //}
}
