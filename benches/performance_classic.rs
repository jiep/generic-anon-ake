use std::time::Duration;

use generic_anon_ake::classic::{
    config::Config,
    protocol::{registration, round_1, round_2, round_3, round_4, round_5, round_6},
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

const SAMPLES: usize = 100;
const LOW_LIMIT: u32 = 6;
const UPP_LIMIT: u32 = 17; // Fix: Change to 17
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
            |b, _| b.iter(|| round_3(&mut client, false)),
        );

        let _x4 = (0, 0);
        group.bench_with_input(
            BenchmarkId::new("Round 4", parameter_string.clone()),
            &_x4,
            |b, _| b.iter(|| round_4(&mut server)),
        );

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

criterion_group!(benches, bench_1);
criterion_main!(benches);
