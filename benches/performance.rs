use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use anon_sym_ake::{
    client::Client,
    config::Config,
    protocol::{registration, round_1, round_2, round_3, round_4},
    server::Server,
    supported_algs::{get_kem_algorithm, get_signature_algorithm, SUPPORTED_KEMS, SUPPORTED_SIGS},
    vrf::vrf_gen_seed_param,
};

// fn benchmark_registration_kyber1024_dilithium_5(c: &mut Criterion) {
//     let users: u8 = 5;

//     let kemalg: Kem = kem::Kem::new(kem::Algorithm::Kyber1024).unwrap();
//     let sigalg: Sig = sig::Sig::new(sig::Algorithm::Dilithium5).unwrap();
//     let (seed, param) = vrf_gen_seed_param();
//     let mut config: Config = Config::new(users, seed, param, kemalg, sigalg);
//     let mut clients: Vec<Client> = (0..users).map(Client::new).collect();
//     let mut server: Server = Server::new(&mut config);

//     registration(&mut clients, &mut server, &mut config);

//     c.bench_function(
//         "Bench the registration function with Kyber1024, Dilithium5, and 5 clients",
//         |b| b.iter(|| registration(&mut clients, &mut server, &mut config)),
//     );
// }

// fn benchmark_round1_kyber1024_dilithium_5(c: &mut Criterion) {
//     let users: u8 = 5;

//     let kemalg: Kem = kem::Kem::new(kem::Algorithm::Kyber1024).unwrap();
//     let sigalg: Sig = sig::Sig::new(sig::Algorithm::Dilithium5).unwrap();
//     let (seed, param) = vrf_gen_seed_param();
//     let mut config: Config = Config::new(users, seed, param, kemalg, sigalg);
//     let mut clients: Vec<Client> = (0..users).map(Client::new).collect();
//     let mut server: Server = Server::new(&mut config);

//     registration(&mut clients, &mut server, &mut config);

//     let mut client0 = clients[0].clone();

//     round_1(&mut client0);

//     client0.send_m1(&mut server);

//     c.bench_function(
//         "Bench the round1 function with Kyber1024, Dilithium5, and 5 clients",
//         |b| b.iter(|| round_1(&mut client0)),
//     );
// }

// fn benchmark_round2_kyber1024_dilithium_5(c: &mut Criterion) {
//     let users: u8 = 5;

//     let kemalg: Kem = kem::Kem::new(kem::Algorithm::Kyber1024).unwrap();
//     let sigalg: Sig = sig::Sig::new(sig::Algorithm::Dilithium5).unwrap();
//     let (seed, param) = vrf_gen_seed_param();
//     let mut config: Config = Config::new(users, seed, param, kemalg, sigalg);
//     let mut clients: Vec<Client> = (0..users).map(Client::new).collect();
//     let mut server: Server = Server::new(&mut config);

//     registration(&mut clients, &mut server, &mut config);

//     let mut client0 = clients[0].clone();

//     round_1(&mut client0);

//     client0.send_m1(&mut server);

//     c.bench_function(
//         "Bench the round2 function with Kyber1024, Dilithium5, and 5 clients",
//         |b| b.iter(|| round_2(&mut server, &mut config, client0.get_id())),
//     );
// }

// fn benchmark_round3_kyber1024_dilithium_5(c: &mut Criterion) {
//     let users: u8 = 5;

//     let kemalg: Kem = kem::Kem::new(kem::Algorithm::Kyber1024).unwrap();
//     let sigalg: Sig = sig::Sig::new(sig::Algorithm::Dilithium5).unwrap();
//     let (seed, param) = vrf_gen_seed_param();
//     let mut config: Config = Config::new(users, seed, param, kemalg, sigalg);
//     let mut clients: Vec<Client> = (0..users).map(Client::new).collect();
//     let mut server: Server = Server::new(&mut config);

//     registration(&mut clients, &mut server, &mut config);

//     let mut client0 = clients[0].clone();

//     round_1(&mut client0);

//     client0.send_m1(&mut server);

//     let m2 = round_2(&mut server, &mut config, client0.get_id());

//     server.send_m2(m2, &mut client0);

//     c.bench_function(
//         "Bench the round3 function with Kyber1024, Dilithium5, and 5 clients",
//         |b| b.iter(|| round_3(&mut client0, &mut config, false)),
//     );
// }

// fn benchmark_round4_kyber1024_dilithium_5(c: &mut Criterion) {
//     let users: u8 = 5;

//     let kemalg: Kem = kem::Kem::new(kem::Algorithm::Kyber1024).unwrap();
//     let sigalg: Sig = sig::Sig::new(sig::Algorithm::Dilithium5).unwrap();
//     let (seed, param) = vrf_gen_seed_param();
//     let mut config: Config = Config::new(users, seed, param, kemalg, sigalg);
//     let mut clients: Vec<Client> = (0..users).map(Client::new).collect();
//     let mut server: Server = Server::new(&mut config);

//     registration(&mut clients, &mut server, &mut config);
//     let mut client0 = clients[0].clone();
//     round_1(&mut client0);
//     client0.send_m1(&mut server);
//     let m2 = round_2(&mut server, &mut config, client0.get_id());
//     server.send_m2(m2, &mut client0);
//     let m3 = round_3(&mut client0, &mut config, false);
//     client0.send_m3(m3, &mut server);
//     round_4(&mut server, &mut config, client0.get_id(), false);
//     c.bench_function(
//         "Bench the round4 function with Kyber1024, Dilithium5, and 5 clients",
//         |b| b.iter(|| round_4(&mut server, &mut config, client0.get_id(), false)),
//     );
// }

fn bench_1(c: &mut Criterion) {
    let mut group = c.benchmark_group("Protocol");

    group.measurement_time(Duration::from_secs(1));

    for users in [255, 128, 64, 32, 16, 8, 4] {
        for kemalg_str in SUPPORTED_KEMS {
            for sigalg_str in SUPPORTED_SIGS {
                let kemalg = get_kem_algorithm(kemalg_str).unwrap();
                let sigalg = get_signature_algorithm(sigalg_str).unwrap();
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

                let m3 = round_3(&mut client0, &mut config, false);
                client0.send_m3(m3, &mut server);

                round_4(&mut server, &mut config, client0.get_id(), false);

                let parameter_string = format!("{}-{}-{}", kemalg_str, sigalg_str, users);
                let _x0 = (0, 0);
                group.bench_with_input(
                    BenchmarkId::new("Registration", parameter_string.clone()),
                    &_x0,
                    |b, _| b.iter(|| registration(&mut clients, &mut server, &mut config)),
                );

                let _x1 = (0, 0);
                group.bench_with_input(
                    BenchmarkId::new("Round 1", parameter_string.clone()),
                    &_x1,
                    |b, (_, _)| b.iter(|| round_1(&mut client0)),
                );

                let _x2 = (0, 0);
                group.bench_with_input(
                    BenchmarkId::new("Round 2", parameter_string.clone()),
                    &_x2,
                    |b, (_, _)| b.iter(|| round_2(&mut server, &mut config, client0.get_id())),
                );

                // let _x3 = (0, 0);
                // group.bench_with_input(BenchmarkId::new("Round 3", parameter_string.clone()), &_x3,
                //     |b, (_, _) | b.iter(|| round_3(&mut client0, &mut config, false)));

                // let _x4 = (0, 0);
                // group.bench_with_input(BenchmarkId::new("Round 4", parameter_string.clone()), &_x4,
                //     |b, (_, _) | b.iter(|| round_4(&mut server, &mut config, client0.get_id(), false)));
            }
        }
    }
    group.finish();
}

fn bench_2(c: &mut Criterion) {
    let mut group = c.benchmark_group("Protocol");

    group.measurement_time(Duration::from_secs(1));

    for users in [255, 128, 64, 32, 16, 8, 4] {
        for kemalg_str in SUPPORTED_KEMS {
            for sigalg_str in SUPPORTED_SIGS {
                let kemalg = get_kem_algorithm(kemalg_str).unwrap();
                let sigalg = get_signature_algorithm(sigalg_str).unwrap();
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

                let m3 = round_3(&mut client0, &mut config, false);
                client0.send_m3(m3, &mut server);

                round_4(&mut server, &mut config, client0.get_id(), false);

                let parameter_string = format!("{}-{}-{}", kemalg_str, sigalg_str, users);
                // let _x0 = (0, 0);
                // group.bench_with_input(BenchmarkId::new("Registration", parameter_string.clone()), &_x0,
                //     |b, _| b.iter(|| registration(&mut clients, &mut server, &mut config)));

                // let _x1 = (0, 0);
                // group.bench_with_input(BenchmarkId::new("Round 1", parameter_string.clone()), &_x1,
                //     |b, (_, _) | b.iter(|| round_1(&mut client0)));

                // let _x2 = (0, 0);
                // group.bench_with_input(BenchmarkId::new("Round 2", parameter_string.clone()), &_x2,
                //     |b, (_, _) | b.iter(|| round_2(&mut server, &mut config, client0.get_id())));

                let _x3 = (0, 0);
                group.bench_with_input(
                    BenchmarkId::new("Round 3", parameter_string.clone()),
                    &_x3,
                    |b, (_, _)| b.iter(|| round_3(&mut client0, &mut config, false)),
                );

                let _x4 = (0, 0);
                group.bench_with_input(
                    BenchmarkId::new("Round 4", parameter_string.clone()),
                    &_x4,
                    |b, (_, _)| {
                        b.iter(|| round_4(&mut server, &mut config, client0.get_id(), false))
                    },
                );
            }
        }
    }
    group.finish();
}

criterion_group!(
    benches, bench_1,
    bench_2 // benchmark_registration_kyber1024_dilithium_5,
            // benchmark_round1_kyber1024_dilithium_5,
            // benchmark_round2_kyber1024_dilithium_5,
            // benchmark_round3_kyber1024_dilithium_5,
            // benchmark_round4_kyber1024_dilithium_5
);
criterion_main!(benches);
