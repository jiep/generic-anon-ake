use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use anon_sym_ake::{
    protocol::client::Client,
    protocol::config::Config,
    protocol::protocol::{registration, round_1, round_2, round_3, round_4},
    protocol::server::Server,
    protocol::supported_algs::get_kem_algorithm,
    protocol::vrf::vrf_gen_seed_param,
};

fn bench_1(c: &mut Criterion) {
    let mut group = c.benchmark_group("Protocol");

    group.measurement_time(Duration::from_secs(1));

    for users in [255] {
        for kemalg_str in ["Kyber1024"] {
            // let kemalg = get_kem_algorithm(kemalg_str).unwrap();
            // let sigalg = get_signature_algorithm(sigalg_str).unwrap();
            // let (seed, param) = vrf_gen_seed_param();
            // let mut config: Config = Config::new(users, seed, param, kemalg, sigalg);
            // let mut clients: Vec<Client> = (0..users).map(Client::new).collect();
            // let mut server: Server = Server::new(&mut config);

            // registration(&mut clients, &mut server, &mut config);

            // let mut client0 = clients[0].clone();

            // let m1 = round_1(&mut client0);
            // client0.send_m1(m1, &mut server);

            // let m2 = round_2(&mut server, &mut config, client0.get_id());
            // server.send_m2(m2, &mut client0);

            // let m3 = round_3(&mut client0, &mut config, false);
            // client0.send_m3(m3, &mut server);

            // round_4(&mut server, &mut config, client0.get_id(), false);

            // let parameter_string = format!("{}-{}-{}", kemalg_str, sigalg_str, users);
            // let _x0 = (0, 0);
            // group.bench_with_input(
            //     BenchmarkId::new("Registration", parameter_string.clone()),
            //     &_x0,
            //     |b, _| b.iter(|| registration(&mut clients, &mut server, &mut config)),
            // );

            // let _x1 = (0, 0);
            // group.bench_with_input(
            //     BenchmarkId::new("Round 1", parameter_string.clone()),
            //     &_x1,
            //     |b, (_, _)| b.iter(|| round_1(&mut client0)),
            // );

            // let _x2 = (0, 0);
            // group.bench_with_input(
            //     BenchmarkId::new("Round 2", parameter_string.clone()),
            //     &_x2,
            //     |b, (_, _)| b.iter(|| round_2(&mut server, &mut config, client0.get_id())),
            // );
        }
    }
    group.finish();
}

fn bench_2(c: &mut Criterion) {
    let mut group = c.benchmark_group("Protocol");

    group.measurement_time(Duration::from_secs(1));

    for users in [255] {
        for kemalg_str in ["Kyber1024"] {
            //     let kemalg = get_kem_algorithm(kemalg_str).unwrap();
            //     let sigalg = get_signature_algorithm(sigalg_str).unwrap();
            //     let (seed, param) = vrf_gen_seed_param();
            //     let mut config: Config = Config::new(users, seed, param, kemalg, sigalg);
            //     let mut clients: Vec<Client> = (0..users).map(Client::new).collect();
            //     let mut server: Server = Server::new(&mut config);

            //     registration(&mut clients, &mut server, &mut config);

            //     let mut client0 = clients[0].clone();

            //     let m1 = round_1(&mut client0);
            //     client0.send_m1(m1, &mut server);

            //     let m2 = round_2(&mut server, &mut config, client0.get_id());
            //     server.send_m2(m2, &mut client0);

            //     let m3 = round_3(&mut client0, &mut config, false);
            //     client0.send_m3(m3, &mut server);

            //     round_4(&mut server, &mut config, client0.get_id(), false);

            //     let parameter_string = format!("{}-{}-{}", kemalg_str, sigalg_str, users);

            //     let _x3 = (0, 0);
            //     group.bench_with_input(
            //         BenchmarkId::new("Round 3", parameter_string.clone()),
            //         &_x3,
            //         |b, (_, _)| b.iter(|| round_3(&mut client0, &mut config, false)),
            //     );

            //     let _x4 = (0, 0);
            //     group.bench_with_input(
            //         BenchmarkId::new("Round 4", parameter_string.clone()),
            //         &_x4,
            //         |b, (_, _)| {
            //             b.iter(|| round_4(&mut server, &mut config, client0.get_id(), false))
            //         },
            //     );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_1, bench_2);
criterion_main!(benches);
