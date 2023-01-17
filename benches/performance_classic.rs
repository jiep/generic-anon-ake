use std::{fs, time::Duration};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use generic_anon_ake::classic::{
    config::Config,
    protocol::{
        get_m1_length, get_m2_length, get_m3_length, get_m4_length, get_m5_length, registration,
        round_1, round_2, round_3, round_4, round_5, round_6,
    },
};

const SAMPLES: usize = 10;
const LOW_LIMIT: u32 = 6;
const UPP_LIMIT: u32 = 11; // Fix: Change to 17
const WARMUP: u64 = 1;

fn bench_1(c: &mut Criterion) {
    let mut group = c.benchmark_group("Protocol_Classic");

    group.measurement_time(Duration::from_secs(WARMUP));
    group.sample_size(SAMPLES);

    for users in (LOW_LIMIT..UPP_LIMIT)
        .map(|x| 2_u32.pow(x))
        .rev()
        .collect::<Vec<u32>>()
    {
        let config: Config = Config::new(users);
        let mut lengths = vec![];

        let (mut server, mut client) = registration(&config);

        let m1 = round_1(&mut client);
        lengths.push(get_m1_length(&m1));
        client.send_m1(m1, &mut server);

        let m2 = round_2(&mut server, &config, client.get_id());
        lengths.push(get_m2_length(&m2));
        server.send_m2(m2, &mut client);

        let m3 = round_3(&mut client, false);
        lengths.push(get_m3_length(&m3));
        client.send_m3(m3, &mut server);

        let m4 = round_4(&mut server);
        lengths.push(get_m4_length(&m4));
        server.send_m4(m4, &mut client);

        let m5 = round_5(&mut client, &config, false);
        lengths.push(get_m5_length(&m5));
        client.send_m5(m5, &mut server);

        round_6(&mut server, client.get_id(), false);

        let data = lengths
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(",");
        let filename = format!(
            "target/criterion/classic-{}-{}-{}.csv",
            "ECIES", "ECDSA", users
        );
        fs::write(filename, data).expect("Unable to write file");

        let parameter_string = format!("{}", users);

        // let _x0 = (0, 0);
        // group.bench_with_input(
        //     BenchmarkId::new("Registration", parameter_string.clone()),
        //     &_x0,
        //     |b, _| b.iter(|| registration(&config)),
        // );

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
            |b, _| b.iter(|| round_3(&mut client, false)),
        );

        let _x4 = (0, 0);
        group.bench_with_input(
            BenchmarkId::new("Round 4", parameter_string.clone()),
            &_x4,
            |b, _| b.iter(|| round_4(&mut server)),
        );
    }
    group.finish();
}

fn bench_2(c: &mut Criterion) {
    let mut group = c.benchmark_group("Protocol_Classic");

    group.measurement_time(Duration::from_secs(WARMUP));
    group.sample_size(SAMPLES);

    for users in (LOW_LIMIT..UPP_LIMIT)
        .map(|x| 2_u32.pow(x))
        .rev()
        .collect::<Vec<u32>>()
    {
        let config: Config = Config::new(users);

        let (mut server, mut client) = registration(&config);

        let m1 = round_1(&mut client);
        client.send_m1(m1, &mut server);

        let m2 = round_2(&mut server, &config, client.get_id());
        server.send_m2(m2, &mut client);

        let m3 = round_3(&mut client, false);
        client.send_m3(m3, &mut server);

        let m4 = round_4(&mut server);

        server.send_m4(m4, &mut client);

        let m5 = round_5(&mut client, &config, false);
        client.send_m5(m5, &mut server);

        round_6(&mut server, client.get_id(), false);

        let parameter_string = format!("{}", users);

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
            |b, _| b.iter(|| round_6(&mut server, client.get_id(), false)),
        );
    }
    group.finish();
}

criterion_group!(benches, bench_1, bench_2);
criterion_main!(benches);
