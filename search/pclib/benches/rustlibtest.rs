// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use bitvec::prelude::*;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use treesearchlib::{
    automata::{
        pikevm_loop_ring_rc, pikevm_loop_ring_rc_priority, pikevm_ring,
        states::{StatesRingRcFixedUnique, StatesRingRcFixedUniqueRing, StatesRingRcRing},
        thread::ThreadRc,
        Results,
    },
    bitstructs::AddressedBits,
    bitstructs::Pattern as BitPattern,
};

use pclib::patternmeta::PatternMeta;

fn get_test_dir_path() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("../treesearchtool/tests/");
    d
}

fn test_meta_pattern(
    file: &str,
    automata: fn(usize, &BitPattern<Msb0>, &AddressedBits) -> Results,
) -> BTreeMap<String, Vec<Results>> {
    let mut test_file = get_test_dir_path();
    test_file.push(file);
    // let pattern_data = fs::read(test_file.as_path()).unwrap();
    // let pattern: Pattern = serde_json::from_slice(&pattern_data).unwrap();
    let pattern: PatternMeta<Msb0> =
        PatternMeta::load_pattern_meta(test_file.as_path().to_str().unwrap());

    let random_bytes: Vec<u8> = (0..2000).map(|_| rand::random::<u8>()).collect();
    // let random_bytes = vec![0u8; 1000];
    return pattern.run_patterns_data_automata(false, random_bytes.as_slice(), automata);
}

fn test_meta_pattern_new(file: &str) -> BTreeMap<String, Vec<Results>> {
    let mut test_file = get_test_dir_path();
    test_file.push(file);
    // let pattern_data = fs::read(test_file.as_path()).unwrap();
    // let pattern: Pattern = serde_json::from_slice(&pattern_data).unwrap();
    let pattern: PatternMeta<Msb0> =
        PatternMeta::load_pattern_meta(test_file.as_path().to_str().unwrap());

    let random_bytes: Vec<u8> = (0..2000).map(|_| rand::random::<u8>()).collect();
    // let random_bytes = vec![0u8; 1000];
    return pattern.run_patterns_data(false, random_bytes.as_slice());
}

pub fn criterion_benchmark(c: &mut Criterion) {
    type EngineHash<'a> = HashMap<&'a str, fn(usize, &BitPattern<Msb0>, &AddressedBits) -> Results>;
    let mut engines: EngineHash = HashMap::new();
    // engines.insert("pikevm", pikevm::run_program);
    engines.insert("pikevm_ring", pikevm_ring::run_program);
    engines.insert(
        "pikevm_loop_ring_rc__StatesRingRcRing",
        pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcRing<ThreadRc>>,
    );
    // engines.insert(
    //     "pikevm_loop_ring_rc__StatesRingRcFixed",
    //     pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixed<ThreadRc, 60, 100>>,
    // );
    engines.insert(
        "pikevm_loop_ring_rc__StatesRingRcFixedUnique",
        pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixedUnique<ThreadRc, 100, 100>>,
    );
    engines.insert(
        "pikevm_loop_ring_rc__StatesRingRcFixedUniqueRing",
        pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixedUniqueRing<ThreadRc, 100, 100>>,
    );
    engines.insert(
        "pikevm_loop_ring_rc_priority__StatesRingRcRing",
        pikevm_loop_ring_rc_priority::run_program::<Msb0, StatesRingRcRing<ThreadRc>>,
    );
    engines.insert(
        "pikevm_loop_ring_rc_priority__StatesRingRcFixedUnique",
        pikevm_loop_ring_rc_priority::run_program::<
            Msb0,
            StatesRingRcFixedUnique<ThreadRc, 100, 100>,
        >,
    );
    engines.insert(
        "pikevm_loop_ring_rc_priority__StatesRingRcFixedUniqueRing",
        pikevm_loop_ring_rc_priority::run_program::<
            Msb0,
            StatesRingRcFixedUniqueRing<ThreadRc, 100, 100>,
        >,
    );

    let mut group = c.benchmark_group("Meta_CVE-2019-3822.json");
    group.sample_size(20);
    for (engine_name, v) in engines.iter() {
        group.bench_with_input(BenchmarkId::new(*engine_name, 0), v, |b, engine| {
            b.iter(|| {
                test_meta_pattern(
                    "../../../example_patterns/CVE-2019-3822/CVE-2019-3822.json",
                    *engine,
                )
            })
        });
    }
    group.bench_with_input(
        BenchmarkId::new("pikevm_loop_ring_rc_priority", 0),
        &pikevm_loop_ring_rc_priority::run_program::<Msb0, StatesRingRcRing<ThreadRc>>,
        |b, _engine| {
            b.iter(|| {
                test_meta_pattern_new("../../../example_patterns/CVE-2019-3822/CVE-2019-3822.json")
            })
        },
    );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
