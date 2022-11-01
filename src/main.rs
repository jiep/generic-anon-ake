pub mod client;
pub mod commitment;
pub mod config;
pub mod pke;
pub mod protocol;
pub mod server;
pub mod utils;

use oqs::{kem, sig};

use crate::client::Client;
use crate::config::Config;
use crate::protocol::{registration, round_1, round_2, round_3, round_4};
use crate::server::Server;
use crate::utils::print_hex;

fn main() {
    // 0. Registration
    println!("0. Registration");
    let users: u8 = 3;

    // Init VRF - Not Post Quantum with this library
    // let vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();

    // Init PQ signature scheme
    let sigalg = sig::Sig::new(sig::Algorithm::Dilithium2).unwrap();

    // Init PQ KEM
    let kemalg = kem::Kem::new(kem::Algorithm::Kyber512).unwrap();

    let mut config: Config = Config::new(users, /* vrf, */ kemalg, sigalg);
    let mut client1: Client = Client::new(1);
    let client2: Client = Client::new(2);
    let client3: Client = Client::new(3);

    let mut clients: Vec<Client> = vec![client1.clone(), client2, client3];
    let mut server: Server = Server::new(&mut config);

    registration(&mut clients, &mut server, &mut config);

    round_1(&mut client1);
    let (comm, open) = client1.get_commitment();
    print_hex(&comm, "comm");
    print_hex(&open, "open");

    client1.send_m1(&mut server);

    let m2 = round_2(&mut server, &mut config);

    server.send_m2(m2, &mut client1);

    round_3(&mut client1, &mut config, &server);

    client1.send_m3(&mut server, &mut config);

    round_4(&mut server, &mut config, 1);
}
