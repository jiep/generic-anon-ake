use std::process;
use std::time::Instant;

use clap::Parser;

use anon_sym_ake::protocol::client::Client;
use anon_sym_ake::protocol::config::Config;
use anon_sym_ake::protocol::protocol::{registration, round_1, round_2, round_3, round_4};
use anon_sym_ake::protocol::server::Server;
use anon_sym_ake::protocol::supported_algs::{
    get_kem_algorithm, get_signature_algorithm, print_supported_kems, print_supported_signatures,
};
use anon_sym_ake::protocol::utils::print_hex;
use anon_sym_ake::protocol::vrf::vrf_gen_seed_param;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    kem: String,

    #[arg(short, long)]
    sig: String,

    #[arg(short, long)]
    #[arg(value_parser = clap::value_parser!(u8).range(1..))]
    clients: u8,

    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();
    let verbose = args.verbose;

    // Init
    let users: u8 = args.clients;

    // Generate seed and param for PQ (lattice-based) VRF
    if verbose {
        println!("[!] Generating param and seed for PQ VRF...");
    }
    let (seed, param) = vrf_gen_seed_param();

    // Init PQ signature scheme
    println!("[!] Setting {} as signature scheme...", args.sig);
    let sigalg = get_signature_algorithm(&args.sig);
    if sigalg.is_none() {
        println!(
            "[!] Signature {} is invalid or is not supported!\n[!] Suppored signature schemes:",
            args.sig
        );
        print_supported_signatures();
        process::exit(1);
    }
    let sigalg = sigalg.unwrap();

    // Init PQ KEM scheme
    println!("[!] Setting {} as KEM...\n", args.kem);
    let kemalg = get_kem_algorithm(&args.kem);
    if kemalg.is_none() {
        println!(
            "[!] Kem {} is invalid or is not supported!\n[!] Suppored KEMS:",
            args.kem
        );
        print_supported_kems();
        process::exit(1);
    }

    let kemalg = kemalg.unwrap();

    let mut config: Config = Config::new(users, seed, param, kemalg, sigalg);

    if verbose {
        println!("[!] Creating {} clients...", users);
    }

    let mut clients: Vec<Client> = (0..users).map(Client::new).collect();

    if verbose {
        println!("[!] Creating server...\n");
    }
    let mut server: Server = Server::new(&mut config);

    if verbose {
        println!("[R] Creating (ek, vk) for {} clients...\n", users);
    }
    let start = Instant::now();
    registration(&mut clients, &mut server, &mut config);
    let duration = start.elapsed();
    println!(
        "[!] Time elapsed in registration of {} clients is {:?}\n",
        users, duration
    );

    let mut client0 = clients[0].clone();

    if verbose {
        println!("[!] Starting protocol with client0 and server...\n");
        println!("[C] Running Round 1...");
    }
    let start = Instant::now();
    let m1 = round_1(&mut client0);
    let duration = start.elapsed();
    println!("[!] Time elapsed in Round 1 is {:?}", duration);

    if verbose {
        println!("[C -> S] Sending m1 to server...\n");
    }
    client0.send_m1(m1, &mut server);

    if verbose {
        println!("[S] Running Round 2...");
    }
    let start = Instant::now();
    let m2 = round_2(&mut server, &mut config, client0.get_id());
    let duration = start.elapsed();
    println!("[!] Time elapsed in Round 2 is {:?}", duration);

    if verbose {
        println!("[C <- S] Sending m2 to client0...\n");
    }
    server.send_m2(m2, &mut client0);

    if verbose {
        println!("[C] Running Round 3...");
    }
    let start = Instant::now();
    let m3 = round_3(&mut client0, &mut config, verbose);
    let duration = start.elapsed();
    println!("[!] Time elapsed in Round 3 is {:?}", duration);
    if verbose {
        println!("[C -> S] Sending m3 to server...\n");
    }
    client0.send_m3(m3, &mut server);

    if verbose {
        println!("[S] Running Round 4...");
    }
    let start = Instant::now();
    round_4(&mut server, &mut config, client0.get_id(), verbose);
    let duration = start.elapsed();
    println!("[!] Time elapsed in Round 4 is {:?}\n", duration);

    println!("[!] Printing session keys...");
    print_hex(&client0.get_key(), "[C]");
    print_hex(&server.get_key(0), "[S]");
}
