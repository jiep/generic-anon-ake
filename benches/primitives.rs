use std::time::Duration;

use anon_sym_ake::protocol::{
    pke::{pke_dec, pke_enc},
    supported_algs::get_kem_algorithm,
    utils::get_random_key32,
    vrf::{vrf_gen_seed_param, vrf_keypair},
    x_vrf::{x_vrf_eval, x_vrf_gen, x_vrf_vfy},
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use lb_vrf::{lbvrf::LBVRF, VRF};
use qrllib::rust_wrapper::xmss_alt::{
    algsxmss_fast::{xmss_fast_gen_keypair, xmss_fast_sign_msg, BDSState, TreeHashInst},
    hash_functions::HashFunction,
    xmss_common::{xmss_verify_sig, XMSSParams},
};

fn bench_1(c: &mut Criterion) {
    let mut group = c.benchmark_group("PKE");

    group.measurement_time(Duration::from_secs(1));
    group.sample_size(1000);

    for kemalg_str in ["Kyber1024", "Kyber768", "Kyber512"] {
        let kemalg = get_kem_algorithm(kemalg_str).unwrap();
        let (pk, sk) = kemalg.keypair().unwrap();
        let m: Vec<u8> = get_random_key32();
        let (ct_kem, ct_dem, iv_tag) = pke_enc(&kemalg, &pk, &m);

        pke_dec(&kemalg, &sk, &ct_kem, &ct_dem, &iv_tag);

        let parameter_string = format!("{}", kemalg_str);

        let _x0 = (0, 0);
        group.bench_with_input(
            BenchmarkId::new("ENC", parameter_string.clone()),
            &_x0,
            |b, _| b.iter(|| pke_enc(&kemalg, &pk, &m)),
        );

        let _x0 = (0, 0);
        group.bench_with_input(
            BenchmarkId::new("DEC", parameter_string.clone()),
            &_x0,
            |b, _| b.iter(|| pke_dec(&kemalg, &sk, &ct_kem, &ct_dem, &iv_tag)),
        );
    }
    group.finish();
}

fn bench_2(c: &mut Criterion) {
    let mut group = c.benchmark_group("X-VRF");

    group.measurement_time(Duration::from_secs(1));
    group.sample_size(1000);

    let h: u8 = 4;
    let n: u32 = 48;
    let mut seed: [u8; 48] = [0; 48];

    let k: u32 = 2;
    let stack = vec![0; (h as usize + 1) * n as usize];
    let stackoffset: u32 = 0;
    let stacklevels: Vec<u8> = vec![0; h as usize + 1];
    let auth: Vec<u8> = vec![0; (h as usize) * n as usize];
    let keep: Vec<u8> = vec![0; (h >> 1) as usize * n as usize];
    let treehash: Vec<TreeHashInst> = vec![TreeHashInst::default(); h as usize - k as usize];
    let retain: Vec<u8> = vec![0; ((1 << k) - k - 1) as usize * n as usize];

    let mut state = BDSState {
        stack,
        stackoffset,
        stacklevels,
        auth,
        keep,
        treehash,
        retain,
        next_leaf: 0,
    };

    let mut params = XMSSParams::new(32, h.into(), 16, 2).unwrap();

    let x: Vec<u8> = (0..32).collect();

    let (vk, mut ek) = x_vrf_gen(&mut params, &mut state, &mut seed);

    let (y, pi) = x_vrf_eval(&mut ek, &x, &params, &mut state);

    x_vrf_vfy(&vk, &mut x.to_vec(), &y, &pi, &params);

    let parameter_string = format!("");

    let _x0 = (0, 0);
    group.bench_with_input(
        BenchmarkId::new("EVAL", parameter_string.clone()),
        &_x0,
        |b, _| b.iter(|| x_vrf_gen(&mut params, &mut state, &mut seed)),
    );

    let _x0 = (0, 0);
    group.bench_with_input(
        BenchmarkId::new("VFY", parameter_string.clone()),
        &_x0,
        |b, _| b.iter(|| x_vrf_vfy(&vk, &mut x.to_vec(), &y, &pi, &params)),
    );

    group.finish();
}

fn bench_3(c: &mut Criterion) {
    let mut group = c.benchmark_group("X-VRF");

    group.measurement_time(Duration::from_secs(1));
    group.sample_size(1000);

    let h: u8 = 4;
    let n: u32 = 48;
    let mut seed: [u8; 48] = [0; 48];

    let k: u32 = 2;
    let stack = vec![0; (h as usize + 1) * n as usize];
    let stackoffset: u32 = 0;
    let stacklevels: Vec<u8> = vec![0; h as usize + 1];
    let auth: Vec<u8> = vec![0; (h as usize) * n as usize];
    let keep: Vec<u8> = vec![0; (h >> 1) as usize * n as usize];
    let treehash: Vec<TreeHashInst> = vec![TreeHashInst::default(); h as usize - k as usize];
    let retain: Vec<u8> = vec![0; ((1 << k) - k - 1) as usize * n as usize];

    let mut state = BDSState {
        stack,
        stackoffset,
        stacklevels,
        auth,
        keep,
        treehash,
        retain,
        next_leaf: 0,
    };

    let mut params = XMSSParams::new(32, h.into(), 16, 2).unwrap();

    let x: Vec<u8> = (0..32).collect();

    let (vk, mut ek) = x_vrf_gen(&mut params, &mut state, &mut seed);

    let (y, pi) = x_vrf_eval(&mut ek, &x, &params, &mut state);

    x_vrf_vfy(&vk, &mut x.to_vec(), &y, &pi, &params);

    let parameter_string = format!("SHAKE-128");

    let _x0 = (0, 0);
    group.bench_with_input(
        BenchmarkId::new("EVAL", parameter_string.clone()),
        &_x0,
        |b, _| b.iter(|| x_vrf_gen(&mut params, &mut state, &mut seed)),
    );

    let _x0 = (0, 0);
    group.bench_with_input(
        BenchmarkId::new("VFY", parameter_string.clone()),
        &_x0,
        |b, _| b.iter(|| x_vrf_vfy(&vk, &mut x.to_vec(), &y, &pi, &params)),
    );

    group.finish();
}

fn bench_4(c: &mut Criterion) {
    let mut group = c.benchmark_group("XMSS");

    group.measurement_time(Duration::from_secs(1));
    group.sample_size(1000);

    let h: u8 = 4;

    let mut pk: [u8; 64] = [0; 64];
    let mut sk: [u8; 4 + 4 * 32] = [0; 4 + 4 * 32];
    let n: u32 = 48;
    let mut seed: [u8; 48] = [0; 48];

    let k: u32 = 2;
    let stack = vec![0; (h as usize + 1) * n as usize];
    let stackoffset: u32 = 0;
    let stacklevels: Vec<u8> = vec![0; h as usize + 1];
    let auth: Vec<u8> = vec![0; (h as usize) * n as usize];
    let keep: Vec<u8> = vec![0; (h >> 1) as usize * n as usize];
    let treehash: Vec<TreeHashInst> = vec![TreeHashInst::default(); h as usize - k as usize];
    let retain: Vec<u8> = vec![0; ((1 << k) - k - 1) as usize * n as usize];

    let mut state = BDSState {
        stack,
        stackoffset,
        stacklevels,
        auth,
        keep,
        treehash,
        retain,
        next_leaf: 0,
    };
    for hash in vec![
        HashFunction::Shake256,
        HashFunction::Shake128,
        HashFunction::SHA2_256,
    ] {
        let params = XMSSParams::new(32, h.into(), 16, 2).unwrap();
        assert!(
            xmss_fast_gen_keypair(&hash, &params, &mut pk, &mut sk, &mut state, &mut seed,).is_ok()
        );

        let mut msg: [u8; 32] = [0; 32];
        let mut sign: [u8; 10000] = [0; 10000];

        let _x = xmss_fast_sign_msg(&hash, &params, &mut sk, &mut state, &mut sign, &msg, 32);
        let _x = xmss_verify_sig(&hash, &params.wots_par, &mut msg, 32, &sign, &pk, h);

        let parameter_string = match hash {
            HashFunction::SHA2_256 => "SHA-256",
            HashFunction::Shake128 => "SHAKE-128",
            HashFunction::Shake256 => "SHAKE-256",
        };

        let _x0 = (0, 0);
        group.bench_with_input(
            BenchmarkId::new("SIG", parameter_string.clone()),
            &_x0,
            |b, _| {
                b.iter(|| {
                    xmss_fast_sign_msg(&hash, &params, &mut sk, &mut state, &mut sign, &msg, 32)
                })
            },
        );

        let _x0 = (0, 0);
        group.bench_with_input(
            BenchmarkId::new("VFY", parameter_string.clone()),
            &_x0,
            |b, _| b.iter(|| xmss_verify_sig(&hash, &params.wots_par, &mut msg, 32, &sign, &pk, h)),
        );
    }

    group.finish();
}

fn bench_5(c: &mut Criterion) {
    let mut group = c.benchmark_group("LB-VRF");

    group.measurement_time(Duration::from_secs(1));
    group.sample_size(1000);

    let (seed, param) = vrf_gen_seed_param();
    let message: Vec<u8> = get_random_key32();

    assert_eq!(seed.len(), 32);
    assert_ne!(seed, [0u8; 32]);

    let (pk, sk) = vrf_keypair(&seed, &param);

    let proof = <LBVRF as VRF>::prove(&message, param, pk, sk, seed).unwrap();

    <LBVRF as VRF>::verify(&message, param, pk, proof).unwrap();

    let parameter_string = format!("");

    let _x0 = (0, 0);
    group.bench_with_input(
        BenchmarkId::new("EVAL", parameter_string.clone()),
        &_x0,
        |b, _| b.iter(|| <LBVRF as VRF>::prove(&message, param, pk, sk, seed).unwrap()),
    );

    let _x0 = (0, 0);
    group.bench_with_input(
        BenchmarkId::new("VFY", parameter_string.clone()),
        &_x0,
        |b, _| b.iter(|| <LBVRF as VRF>::verify(&message, param, pk, proof).unwrap()),
    );

    group.finish();
}

criterion_group!(benches, bench_1, bench_2, bench_3, bench_4, bench_5);
criterion_main!(benches);
