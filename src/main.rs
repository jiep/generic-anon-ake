pub mod client;
pub mod commitment;
pub mod config;
pub mod pke;
pub mod protocol;
pub mod server;
pub mod utils;
pub mod vrf;

use std::process;

use clap::Parser;
use oqs::{kem, sig};

use crate::client::Client;
use crate::config::Config;
use crate::protocol::{registration, round_1, round_2, round_3, round_4};
use crate::server::Server;
use crate::utils::print_hex;
use crate::vrf::vrf_gen_seed_param;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    kem: String,

    #[arg(short, long)]
    sig: String,

    #[arg(short, long, default_value_t = 3)]
    clients: u8,
}

fn get_kem_algorithm(kem: &String) -> Option<kem::Kem> {
    let kemalg = match kem.as_str() {
        "kyber512" => Some(kem::Kem::new(kem::Algorithm::Kyber512).unwrap()),
        "kyber768" => Some(kem::Kem::new(kem::Algorithm::Kyber768).unwrap()),
        "kyber1024" => Some(kem::Kem::new(kem::Algorithm::Kyber1024).unwrap()),
        _ => None,
    };

    kemalg
}

fn get_signature_algorithm(sig: &String) -> Option<sig::Sig> {
    let sigalg = match sig.as_str() {
        "dilithium2" => Some(sig::Sig::new(sig::Algorithm::Dilithium2).unwrap()),
        "dilithium3" => Some(sig::Sig::new(sig::Algorithm::Dilithium3).unwrap()),
        "dilithium5" => Some(sig::Sig::new(sig::Algorithm::Dilithium5).unwrap()),
        "falcon512" => Some(sig::Sig::new(sig::Algorithm::Falcon512).unwrap()),
        "falcon1024" => Some(sig::Sig::new(sig::Algorithm::Falcon1024).unwrap()),
        "sphincsHaraka128fRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsHaraka128fRobust).unwrap())
        }
        "sphincsHaraka128fSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsHaraka128fSimple).unwrap())
        }
        "sphincsHaraka128sRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsHaraka128sRobust).unwrap())
        }
        "sphincsHaraka128sSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsHaraka128sSimple).unwrap())
        }
        _ => None,
    };

    sigalg
}

fn main() {
    let args = Args::parse();

    // Init
    let users: u8 = args.clients;

    // Generate seed and param for PQ (lattice-based) VRF
    println!("[!] Generating param and seed for PQ VRF...");
    let (seed, param) = vrf_gen_seed_param();

    // Init PQ signature scheme
    println!("[!] Setting {} as signature scheme...", args.sig);
    let sigalg = get_signature_algorithm(&args.sig);
    if sigalg.is_none() {
        println!("[!] Signature {} is invalid or is not supported!", args.sig);
        process::exit(1);
    }
    let sigalg = sigalg.unwrap();

    // Init PQ KEM scheme
    println!("[!] Setting {} as KEM...\n", args.kem);
    let kemalg = get_kem_algorithm(&args.kem);
    if kemalg.is_none() {
        println!("[!] Kem {} is invalid or is not supported!", args.kem);
        process::exit(1);
    }

    let kemalg = kemalg.unwrap();

    let mut config: Config = Config::new(users, seed, param, kemalg, sigalg);

    println!("[!] Creating {} clients...", users);
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

    println!("[C -> S] Sending m1 to server...\n");
    client0.send_m1(&mut server);

    println!("[S] Running Round 2...");
    let m2 = round_2(&mut server, &mut config, client0.get_id());

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
