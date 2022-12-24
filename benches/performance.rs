use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use anon_sym_ake::{
    protocol::config::Config,
    protocol::protocol::{registration, round_1, round_2, round_3, round_4, round_5, round_6},
    protocol::supported_algs::get_kem_algorithm,
    protocol::supported_algs::get_signature_algorithm,
};

const SAMPLES: usize = 100;
const LOW_LIMIT: u32 = 6;
const UPP_LIMIT: u32 = 17;

fn bench_1(c: &mut Criterion) {
    let mut group = c.benchmark_group("Protocol");

    group.measurement_time(Duration::from_secs(1));
    group.sample_size(SAMPLES);

    for users in (LOW_LIMIT..UPP_LIMIT)
        .map(|x| 2_u32.pow(x))
        .rev()
        .collect::<Vec<u32>>()
    {
        for (kemalg_str, sigalg_str) in
            vec![("Kyber1024", "Dilithium5"), ("Kyber768", "Dilithium3")]
        {
            let kemalg = get_kem_algorithm(kemalg_str).unwrap();
            let sigalg = get_signature_algorithm(sigalg_str).unwrap();
            let config: Config = Config::new(users, kemalg, sigalg);

            let (mut server, mut client) = registration(&config);

            let m1 = round_1(&mut client);
            client.send_m1(m1, &mut server);

            let m2 = round_2(&mut server, &config, client.get_id());
            server.send_m2(m2, &mut client);

            let m3 = round_3(&mut client, &config, false);
            client.send_m3(m3, &mut server);

            let m4 = round_4(&mut server, &config);

            server.send_m4(m4, &mut client);

            let m5 = round_5(&mut client, &config, false);
            client.send_m5(m5, &mut server);

            round_6(&mut server, &config, client.get_id(), false);

            let parameter_string = format!("{}-{}-{}", kemalg_str, sigalg_str, users);

            let _x0 = (0, 0);
            group.bench_with_input(
                BenchmarkId::new("Registration", parameter_string.clone()),
                &_x0,
                |b, _| b.iter(|| registration(&config)),
            );

            let _x1 = (0, 0);
            group.bench_with_input(
                BenchmarkId::new("Round 1", parameter_string.clone()),
                &_x1,
                |b, _| b.iter(|| round_1(&mut client)),
            );

            let _x2 = (0, 0);
            group.bench_with_input(
                BenchmarkId::new("Round 2", parameter_string.clone()),
                &_x2,
                |b, _| b.iter(|| round_2(&mut server, &config, client.get_id())),
            );

            let _x3 = (0, 0);
            group.bench_with_input(
                BenchmarkId::new("Round 3", parameter_string.clone()),
                &_x3,
                |b, _| b.iter(|| round_3(&mut client, &config, false)),
            );

            let _x4 = (0, 0);
            group.bench_with_input(
                BenchmarkId::new("Round 4", parameter_string.clone()),
                &_x4,
                |b, _| b.iter(|| round_4(&mut server, &config)),
            );
        }
    }
    group.finish();
}

fn bench_2(c: &mut Criterion) {
    let mut group = c.benchmark_group("Protocol");

    group.measurement_time(Duration::from_secs(1));
    group.sample_size(SAMPLES);

    for users in (LOW_LIMIT..UPP_LIMIT)
        .map(|x| 2_u32.pow(x))
        .rev()
        .collect::<Vec<u32>>()
    {
        for (kemalg_str, sigalg_str) in
            vec![("Kyber1024", "Dilithium5"), ("Kyber768", "Dilithium3")]
        {
            let kemalg = get_kem_algorithm(kemalg_str).unwrap();
            let sigalg = get_signature_algorithm(sigalg_str).unwrap();
            let config: Config = Config::new(users, kemalg, sigalg);

            let (mut server, mut client) = registration(&config);

            let m1 = round_1(&mut client);
            client.send_m1(m1, &mut server);

            let m2 = round_2(&mut server, &config, client.get_id());
            server.send_m2(m2, &mut client);

            let m3 = round_3(&mut client, &config, false);
            client.send_m3(m3, &mut server);

            let m4 = round_4(&mut server, &config);

            server.send_m4(m4, &mut client);

            let m5 = round_5(&mut client, &config, false);
            client.send_m5(m5, &mut server);

            round_6(&mut server, &config, client.get_id(), false);

            let parameter_string = format!("{}-{}-{}", kemalg_str, sigalg_str, users);

            let _x5 = (0, 0);
            group.bench_with_input(
                BenchmarkId::new("Round 5", parameter_string.clone()),
                &_x5,
                |b, _| b.iter(|| round_5(&mut client, &config, false)),
            );

            let _x6 = (0, 0);
            group.bench_with_input(
                BenchmarkId::new("Round 6", parameter_string.clone()),
                &_x6,
                |b, _| b.iter(|| round_6(&mut server, &config, client.get_id(), false)),
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_1, bench_2);
criterion_main!(benches);
