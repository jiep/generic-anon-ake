use std::time::{Duration, Instant};

use clap::Parser;
use generic_anon_ake::common::utils::print_hex;

use generic_anon_ake::classic::config::Config;
use generic_anon_ake::classic::protocol::{
    get_m1_length, get_m2_length, get_m3_length, get_m4_length, get_m5_length, registration,
    round_1, round_2, round_3, round_4, round_5, round_6, show_diagram,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    #[arg(value_parser = clap::value_parser!(u32).range(1..))]
    clients: u32,

    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();
    let verbose = args.verbose;

    let users: u32 = args.clients;

    let mut times: Vec<Duration> = Vec::new();
    let mut lengths: Vec<usize> = Vec::new();

    let config: Config = Config::new(users);

    if verbose {
        println!("[!] Creating {users} clients...");
    }

    if verbose {
        println!("[!] Creating server...\n");
    }

    if verbose {
        println!("[R] Creating (ek, vk) for {users} clients...\n");
    }
    let start = Instant::now();
    let (mut server, mut client) = registration(&config);
    let duration = start.elapsed();
    println!("[!] Time elapsed in registration of {users} clients is {duration:?}\n");
    times.push(duration);

    if verbose {
        println!("[!] Starting protocol with client and server...\n");
        println!("[C] Running Round 1...");
    }
    let start = Instant::now();
    let m1 = round_1(&mut client);
    lengths.push(get_m1_length(&m1));
    let duration = start.elapsed();
    println!("[!] Time elapsed in Round 1 is {duration:?}");
    times.push(duration);

    if verbose {
        println!("[C -> S] Sending m1 to server...\n");
    }
    client.send_m1(m1, &mut server);

    if verbose {
        println!("[S] Running Round 2...");
    }
    let start = Instant::now();
    let m2 = round_2(&mut server, &config, client.get_id());
    lengths.push(get_m2_length(&m2));
    let duration = start.elapsed();
    println!("[!] Time elapsed in Round 2 is {duration:?}");
    times.push(duration);

    if verbose {
        println!("[C <- S] Sending m2 to client...\n");
    }
    server.send_m2(m2, &mut client);

    if verbose {
        println!("[C] Running Round 3...");
    }
    let start = Instant::now();
    let m3 = round_3(&mut client, verbose);
    lengths.push(get_m3_length(&m3));
    let duration = start.elapsed();
    println!("[!] Time elapsed in Round 3 is {duration:?}");
    times.push(duration);
    if verbose {
        println!("[C -> S] Sending m3 to server...\n");
    }
    client.send_m3(m3, &mut server);

    if verbose {
        println!("[S] Running Round 4...");
    }
    let start = Instant::now();
    let m4 = round_4(&mut server);
    lengths.push(get_m4_length(&m4));
    let duration = start.elapsed();
    println!("[!] Time elapsed in Round 4 is {duration:?}");
    times.push(duration);
    if verbose {
        println!("[C <- S] Sending m4 to client...\n");
    }
    server.send_m4(m4, &mut client);

    if verbose {
        println!("[C] Running Round 5...");
    }
    let start = Instant::now();
    let m5 = round_5(&mut client, &config, verbose);
    lengths.push(get_m5_length(&m5));
    let duration = start.elapsed();
    times.push(duration);
    println!("[!] Time elapsed in Round 5 is {duration:?}");
    if verbose {
        println!("[C -> S] Sending m5 to server...\n");
    }
    client.send_m5(m5, &mut server);

    if verbose {
        println!("[S] Running Round 6...");
    }
    let start = Instant::now();
    round_6(&mut server, client.get_id(), verbose);
    let duration = start.elapsed();
    times.push(duration);
    println!("[!] Time elapsed in Round 6 is {duration:?}\n");

    println!("[!] Printing session keys...");
    let key_server = server.get_key(0);
    let key_client = client.get_key();
    print_hex(&key_client, "[C]");
    print_hex(&key_server, "[S]");
    println!();
    println!("[!] Printing session identifiers...");
    let sid_server = server.get_sid(0);
    let sid_client = client.get_sid();
    print_hex(&sid_client, "[C]");
    print_hex(&sid_server, "[S]");
    println!();
    println!("[!] Printing diagram...");
    show_diagram(&times, &lengths, users);
}
