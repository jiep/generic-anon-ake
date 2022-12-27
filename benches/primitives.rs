use std::time::Duration;

use anon_sym_ake::protocol::{
    prf::prf,
    supported_algs::{get_kem_algorithm, get_signature_algorithm},
    utils::get_random_key32, ccpake::{ccapke_enc, ccapke_dec},
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

fn bench_1(c: &mut Criterion) {
    let mut group = c.benchmark_group("PKE");

    group.measurement_time(Duration::from_secs(1));
    group.sample_size(1000);

    for kemalg_str in ["Kyber1024", "Kyber768", "Kyber512"] {
        let kemalg = get_kem_algorithm(kemalg_str).unwrap();
        let (pk, sk) = kemalg.keypair().unwrap();
        let m: Vec<u8> = get_random_key32();
        let (ct_kem, ct_dem, iv_tag) = ccapke_enc(&kemalg, &pk, &m);

        ccapke_dec(&kemalg, sk.clone(), &ct_kem, &ct_dem, &iv_tag);

        let parameter_string = format!("{}", kemalg_str);

        let _x0 = (0, 0);
        group.bench_with_input(
            BenchmarkId::new("KEYGEN", parameter_string.clone()),
            &_x0,
            |b, _| b.iter(|| kemalg.keypair().unwrap()),
        );

        let _x0 = (0, 0);
        group.bench_with_input(
            BenchmarkId::new("ENC", parameter_string.clone()),
            &_x0,
            |b, _| b.iter(|| ccapke_enc(&kemalg, &pk, &m)),
        );

        let _x0 = (0, 0);
        group.bench_with_input(
            BenchmarkId::new("DEC", parameter_string.clone()),
            &_x0,
            |b, _| b.iter(|| ccapke_dec(&kemalg, sk.clone(), &ct_kem, &ct_dem, &iv_tag)),
        );
    }
    group.finish();
}

fn bench_2(c: &mut Criterion) {
    let mut group = c.benchmark_group("PRF");

    let key = get_random_key32();
    let nonce = get_random_key32();

    group.measurement_time(Duration::from_secs(1));
    group.sample_size(1000);

    let parameter_string = format!("");

    let _x0 = (0, 0);
    group.bench_with_input(
        BenchmarkId::new("PRF", parameter_string.clone()),
        &_x0,
        |b, _| b.iter(|| prf(&key, &nonce[0..16])),
    );

    group.finish();
}

fn bench_3(c: &mut Criterion) {
    let mut group = c.benchmark_group("SIG");

    group.measurement_time(Duration::from_secs(1));
    group.sample_size(1000);

    for sigalg_str in ["Dilithium5", "Dilithium3", "Dilithium2"] {
        let sigalg = get_signature_algorithm(sigalg_str).unwrap();
        let (pk, sk) = sigalg.keypair().unwrap();
        let m: Vec<u8> = get_random_key32();
        let signature = sigalg.sign(&m, &sk).unwrap();

        sigalg.verify(&m, &signature, &pk).unwrap();

        let parameter_string = format!("{}", sigalg_str);

        let _x0 = (0, 0);
        group.bench_with_input(
            BenchmarkId::new("KEYGEN", parameter_string.clone()),
            &_x0,
            |b, _| b.iter(|| sigalg.keypair().unwrap()),
        );

        let _x0 = (0, 0);
        group.bench_with_input(
            BenchmarkId::new("SIG", parameter_string.clone()),
            &_x0,
            |b, _| b.iter(|| sigalg.sign(&m, &sk).unwrap()),
        );

        let _x0 = (0, 0);
        group.bench_with_input(
            BenchmarkId::new("VRY", parameter_string.clone()),
            &_x0,
            |b, _| b.iter(|| sigalg.verify(&m, &signature, &pk).unwrap()),
        );
    }
    group.finish();
}

criterion_group!(benches, bench_1, bench_2, bench_3);
criterion_main!(benches);
