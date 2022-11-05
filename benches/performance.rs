use criterion::{criterion_group, criterion_main, Criterion};

use anon_sym_ake::{
    client::Client,
    config::Config,
    protocol::{registration, round_1, round_2, round_3, round_4},
    server::Server,
    vrf::vrf_gen_seed_param,
};
use oqs::{
    kem::{self, Kem},
    sig::{self, Sig},
};

fn benchmark_registration_kyber1024_dilithium_5(c: &mut Criterion) {
    let users: u8 = 5;

    let kemalg: Kem = kem::Kem::new(kem::Algorithm::Kyber1024).unwrap();
    let sigalg: Sig = sig::Sig::new(sig::Algorithm::Dilithium5).unwrap();
    let (seed, param) = vrf_gen_seed_param();
    let mut config: Config = Config::new(users, seed, param, kemalg, sigalg);
    let mut clients: Vec<Client> = (0..users).map(Client::new).collect();
    let mut server: Server = Server::new(&mut config);

    registration(&mut clients, &mut server, &mut config);

    c.bench_function(
        "Bench the registration function with Kyber1024, Dilithium5, and 5 clients",
        |b| b.iter(|| registration(&mut clients, &mut server, &mut config)),
    );
}

fn benchmark_round1_kyber1024_dilithium_5(c: &mut Criterion) {
    let users: u8 = 5;

    let kemalg: Kem = kem::Kem::new(kem::Algorithm::Kyber1024).unwrap();
    let sigalg: Sig = sig::Sig::new(sig::Algorithm::Dilithium5).unwrap();
    let (seed, param) = vrf_gen_seed_param();
    let mut config: Config = Config::new(users, seed, param, kemalg, sigalg);
    let mut clients: Vec<Client> = (0..users).map(Client::new).collect();
    let mut server: Server = Server::new(&mut config);

    registration(&mut clients, &mut server, &mut config);

    let mut client0 = clients[0].clone();

    round_1(&mut client0);

    client0.send_m1(&mut server);

    c.bench_function(
        "Bench the round1 function with Kyber1024, Dilithium5, and 5 clients",
        |b| b.iter(|| round_1(&mut client0)),
    );
}

fn benchmark_round3_kyber1024_dilithium_5(c: &mut Criterion) {
    let users: u8 = 5;

    let kemalg: Kem = kem::Kem::new(kem::Algorithm::Kyber1024).unwrap();
    let sigalg: Sig = sig::Sig::new(sig::Algorithm::Dilithium5).unwrap();
    let (seed, param) = vrf_gen_seed_param();
    let mut config: Config = Config::new(users, seed, param, kemalg, sigalg);
    let mut clients: Vec<Client> = (0..users).map(Client::new).collect();
    let mut server: Server = Server::new(&mut config);

    registration(&mut clients, &mut server, &mut config);

    let mut client0 = clients[0].clone();

    round_1(&mut client0);

    client0.send_m1(&mut server);

    let m2 = round_2(&mut server, &mut config, client0.get_id());

    server.send_m2(m2, &mut client0);

    c.bench_function(
        "Bench the round3 function with Kyber1024, Dilithium5, and 5 clients",
        |b| b.iter(|| round_3(&mut client0, &mut config)),
    );
}

fn benchmark_round4_kyber1024_dilithium_5(c: &mut Criterion) {
    let users: u8 = 5;

    let kemalg: Kem = kem::Kem::new(kem::Algorithm::Kyber1024).unwrap();
    let sigalg: Sig = sig::Sig::new(sig::Algorithm::Dilithium5).unwrap();
    let (seed, param) = vrf_gen_seed_param();
    let mut config: Config = Config::new(users, seed, param, kemalg, sigalg);
    let mut clients: Vec<Client> = (0..users).map(Client::new).collect();
    let mut server: Server = Server::new(&mut config);

    registration(&mut clients, &mut server, &mut config);
    let mut client0 = clients[0].clone();
    round_1(&mut client0);
    client0.send_m1(&mut server);
    let m2 = round_2(&mut server, &mut config, client0.get_id());
    server.send_m2(m2, &mut client0);
    let m3 = round_3(&mut client0, &mut config);
    client0.send_m3(m3, &mut server);
    round_4(&mut server, &mut config, client0.get_id());
    c.bench_function(
        "Bench the round4 function with Kyber1024, Dilithium5, and 5 clients",
        |b| b.iter(|| round_4(&mut server, &mut config, client0.get_id())),
    );
}

criterion_group!(
    benches,
    benchmark_registration_kyber1024_dilithium_5,
    benchmark_round1_kyber1024_dilithium_5,
    benchmark_round3_kyber1024_dilithium_5,
    benchmark_round4_kyber1024_dilithium_5
);
criterion_main!(benches);
