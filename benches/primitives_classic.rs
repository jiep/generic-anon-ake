use std::time::Duration;

use anon_sym_ake::{common::utils::get_random_key32, classic::{ccapke::{ccapke_gen, ccapke_enc, ccapke_dec}, sig::{sig_gen, sig_sign, sig_vry}}};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

fn bench_1(c: &mut Criterion) {
    let mut group = c.benchmark_group("PKE_CLASSIC");

    group.measurement_time(Duration::from_secs(1));
    group.sample_size(1000);

    let (pk, sk) = ccapke_gen();
    let m: Vec<u8> = get_random_key32();
    let ct = ccapke_enc(&pk, &m);

    ccapke_dec(&sk, &ct);

    let parameter_string = format!("");

    let _x0 = (0, 0);
    group.bench_with_input(
        BenchmarkId::new("KEYGEN", parameter_string.clone()),
        &_x0,
        |b, _| b.iter(|| ccapke_gen()),
    );

    let _x0 = (0, 0);
    group.bench_with_input(
        BenchmarkId::new("ENC", parameter_string.clone()),
        &_x0,
        |b, _| b.iter(|| ccapke_enc(&pk, &m)),
    );

    let _x0 = (0, 0);
    group.bench_with_input(
        BenchmarkId::new("DEC", parameter_string.clone()),
        &_x0,
        |b, _| b.iter(|| ccapke_dec(&sk, &ct)),
    );

    group.finish();
}

fn bench_2(c: &mut Criterion) {
    let mut group = c.benchmark_group("SIG_CLASSIC");

    group.measurement_time(Duration::from_secs(1));
    group.sample_size(1000);

    let (pk, sk) = sig_gen();
    let m: Vec<u8> = get_random_key32();
    let signature = sig_sign(&sk, &m);

    sig_vry(&pk, &m, &signature);

    let parameter_string = format!("");

    let _x0 = (0, 0);
    group.bench_with_input(
        BenchmarkId::new("KEYGEN", parameter_string.clone()),
        &_x0,
        |b, _| b.iter(|| sig_gen()),
    );

    let _x0 = (0, 0);
    group.bench_with_input(
        BenchmarkId::new("SIG", parameter_string.clone()),
        &_x0,
        |b, _| b.iter(|| sig_sign(&sk, &m)),
    );

    let _x0 = (0, 0);
    group.bench_with_input(
        BenchmarkId::new("VRY", parameter_string.clone()),
        &_x0,
        |b, _| b.iter(|| sig_vry(&pk, &m, &signature)),
    );

    group.finish();
}

criterion_group!(benches, bench_1, bench_2);
criterion_main!(benches);