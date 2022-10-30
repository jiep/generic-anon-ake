pub struct Server {
    clients_keys: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Server {
    /* pub fn new(clients_keys: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        Server { clients_keys }
    } */

    pub fn new() -> Self {
        Server {
            clients_keys: Vec::new(),
        }
    }

    pub fn add_key(&mut self, key: (Vec<u8>, Vec<u8>)) {
        self.clients_keys.push(key);
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}
