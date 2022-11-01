pub mod client;
pub mod commitment;
pub mod config;
pub mod pke;
pub mod protocol;
pub mod server;
pub mod utils;
pub mod vrf;

use oqs::{kem, sig};

use crate::client::Client;
use crate::config::Config;
use crate::protocol::{registration, round_1, round_2, round_3, round_4};
use crate::server::Server;
use crate::utils::print_hex;
use crate::vrf::vrf_gen_seed_param;

fn main() {
    // 0. Registration
    println!("0. Registration");
    let users: u8 = 3;

    // Generate seed and param for PQ (lattice-based) VRF
    let (seed, param) = vrf_gen_seed_param();

    // Init PQ signature scheme
    let sigalg = sig::Sig::new(sig::Algorithm::Dilithium2).unwrap();

    // Init PQ KEM
    let kemalg = kem::Kem::new(kem::Algorithm::Kyber512).unwrap();

    let mut config: Config = Config::new(users, seed, param, kemalg, sigalg);
    let mut client1: Client = Client::new(1);
    let mut client2: Client = Client::new(2);
    let mut client3: Client = Client::new(3);

    let clients: Vec<&mut Client> = vec![&mut client1, &mut client2, &mut client3];
    let mut server: Server = Server::new(&mut config);

    registration(clients, &mut server, &mut config);

    round_1(&mut client1);

    let (comm, open) = client1.get_commitment();
    print_hex(&comm, "comm");
    print_hex(&open, "open");

    client1.send_m1(&mut server);

    let m2 = round_2(&mut server, &mut config);

    server.send_m2(m2, &mut client1);

    let m3 = round_3(&mut client1, &mut config);

    client1.send_m3(m3, &mut server);

    round_4(&mut server, &mut config, 1);

    println!("server: {:#?}", server);
    println!("client1: {:#?}", client1);
}
