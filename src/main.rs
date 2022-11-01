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
    // Init
    let users: u8 = 3;

    // Generate seed and param for PQ (lattice-based) VRF
    println!("[!] Generating param and seed for PQ VRF...");
    let (seed, param) = vrf_gen_seed_param();

    // Init PQ signature scheme
    println!("[!] Setting Dilithium2 as signature scheme...");
    let sigalg = sig::Sig::new(sig::Algorithm::Dilithium2).unwrap();

    // Init PQ KEM
    println!("[!] Setting Kyber512 as KEM...\n");
    let kemalg = kem::Kem::new(kem::Algorithm::Kyber512).unwrap();

    let mut config: Config = Config::new(users, seed, param, kemalg, sigalg);

    println!("[!] Creating 3 clients with id 0, 1, and 2...");
    let mut client0: Client = Client::new(0);
    let mut client1: Client = Client::new(1);
    let mut client2: Client = Client::new(2);

    let clients: Vec<&mut Client> = vec![&mut client0, &mut client1, &mut client2];

    println!("[!] Creating server...\n");
    let mut server: Server = Server::new(&mut config);

    println!("[R] Creating (ek, vk) for clients 0, 1, and 2...\n");
    registration(clients, &mut server, &mut config);

    println!("[!] Starting protocol with client0 and server...\n");
    println!("[C] Running Round 1...");
    round_1(&mut client0);

    // Fix: add to m1
    let _ = client0.get_commitment();
    // print_hex(&comm, "comm");
    // print_hex(&open, "open");

    println!("[C -> S] Sending m1 to server...\n");
    client0.send_m1(&mut server);

    println!("[S] Running Round 2...");
    let m2 = round_2(&mut server, &mut config);

    println!("[C <- S] Sending m2 to client0...\n");
    server.send_m2(m2, &mut client0);

    println!("[C] Running Round 3...");
    let m3 = round_3(&mut client0, &mut config);

    println!("[C -> S] Sending m3 to server...\n");
    client0.send_m3(m3, &mut server);

    println!("[C] Running Round 4...\n");
    round_4(&mut server, &mut config, client0.get_id());

    println!("[!] Printing session keys...");
    print_hex(&client0.get_key(), "[C]");
    print_hex(&server.get_key(0), "[S]");
}
