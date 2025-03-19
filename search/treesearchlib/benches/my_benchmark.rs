// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use std::collections::HashMap;

use bitvec::prelude::*;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use treesearchlib::{
    automata::{
        pikevm_loop_ring_rc, pikevm_loop_ring_rc_priority, pikevm_ring,
        states::{StatesRingRcFixedUnique, StatesRingRcFixedUniqueRing, StatesRingRcRing},
        thread::ThreadRc,
        Results,
    },
    b::AddressedBits,
    bitstructs::{InstructionEncoding, LookupType, Op, Pattern},
};

use rand::{thread_rng, Rng};

fn test_bench_helper<Endian: BitOrder + Clone + PartialEq>(
    input_prog: &Pattern<Endian>,
    f: fn(usize, &Pattern<Endian>, &AddressedBits) -> Results,
) {
    let mut prog = Pattern::<Endian>::get_dot_star();
    prog.append(input_prog);
    let mut input = vec![0; 2000];
    input.push(0x3);
    input.push(0x4);
    assert!(f(10, &prog, &input.as_slice().into()).matched);
}

fn lookup_helper<Endian: BitOrder + Clone + PartialEq>(
    input_prog: &Pattern<Endian>,
    f: fn(usize, &Pattern<Endian>, &AddressedBits) -> Results,
) {
    let mut prog = Pattern::<Endian>::get_dot_star();
    prog.append(input_prog);
    let mut input = vec![0; 2000];
    thread_rng().fill(&mut input[..]);
    input.push(0xa2u8);
    input.push(0x77);
    input.push(0x55);
    input.push(0x12);
    assert!(f(10, &prog, &input.as_slice().into()).matched);
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut progs = HashMap::new();
    progs.insert(
        "LotsOfRecursion",
        // Now lets make sure our pike method can handle even the bad case:
        Pattern::<Msb0> {
            steps: vec![
                Op::AnyByte,
                // This the *bad* way! It'll blow up the recursive methods
                Op::Split { dest1: 0, dest2: 2 },
                Op::Byte { value: 0x3 },
                Op::Byte { value: 0x4 },
                Op::Match { match_number: 0 },
            ],
            tables: vec![],
        },
    );
    progs.insert(
        "LotsOfSplits",
        Pattern::<Msb0> {
            steps: vec![
                Op::AnyByte,
                Op::AnyByte,
                Op::AnyByte,
                Op::AnyByte,
                Op::AnyByte,
                Op::AnyByte,
                Op::AnyByte,
                Op::AnyByte,
                Op::AnyByte,
                Op::AnyByte,
                Op::Split {
                    dest1: 11,
                    dest2: 30,
                },
                Op::AnyByte,
                Op::Split {
                    dest1: 13,
                    dest2: 30,
                },
                Op::AnyByte,
                Op::Split {
                    dest1: 15,
                    dest2: 30,
                },
                Op::AnyByte,
                Op::Split {
                    dest1: 17,
                    dest2: 30,
                },
                Op::AnyByte,
                Op::Split {
                    dest1: 19,
                    dest2: 30,
                },
                Op::AnyByte,
                Op::Split {
                    dest1: 21,
                    dest2: 30,
                },
                Op::AnyByte,
                Op::Split {
                    dest1: 23,
                    dest2: 30,
                },
                Op::AnyByte,
                Op::Split {
                    dest1: 25,
                    dest2: 30,
                },
                Op::AnyByte,
                Op::Split {
                    dest1: 27,
                    dest2: 30,
                },
                Op::AnyByte,
                Op::Split {
                    dest1: 29,
                    dest2: 30,
                },
                Op::AnyByte,
                Op::Byte { value: 0x3 },
                Op::Match { match_number: 0 },
            ],
            tables: vec![],
        },
    );

    progs.insert(
        "AnyByteSeqence",
        Pattern::<Msb0> {
            steps: vec![
                Op::AnyByteSequence {
                    min: 10,
                    max: 20,
                    interval: 1,
                },
                Op::Byte { value: 0x3 },
                Op::Match { match_number: 0 },
            ],
            tables: vec![],
        },
    );

    type EngineHash<'a> = HashMap<&'a str, fn(usize, &Pattern<Msb0>, &AddressedBits) -> Results>;
    let mut engines: EngineHash = HashMap::new();

    // engines.insert("pikevm", pikevm::run_program);
    engines.insert("pikevm_ring", pikevm_ring::run_program);
    engines.insert(
        "pikevm_loop_ring_rc__StatesRingRcRing",
        pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcRing<ThreadRc>>,
    );
    // engines.insert(
    //     "pikevm_loop_ring_rc__StatesRingRcFixed",
    //     pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixed<ThreadRc, 50, 100>>,
    // );
    engines.insert(
        "pikevm_loop_ring_rc__StatesRingRcFixedUnique",
        pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixedUnique<ThreadRc, 50, 100>>,
    );
    engines.insert(
        "pikevm_loop_ring_rc__StatesRingRcFixedUniqueRing",
        pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixedUniqueRing<ThreadRc, 50, 100>>,
    );
    engines.insert(
        "pikevm_loop_ring_rc_priority__StatesRingRcRing",
        pikevm_loop_ring_rc_priority::run_program::<Msb0, StatesRingRcRing<ThreadRc>>,
    );
    engines.insert(
        "pikevm_loop_ring_rc_priority__StatesRingRcFixedUnique",
        pikevm_loop_ring_rc_priority::run_program::<Msb0, StatesRingRcFixedUnique<ThreadRc, 50, 100>>,
    );
    engines.insert(
        "pikevm_loop_ring_rc_priority__StatesRingRcFixedUniqueRing",
        pikevm_loop_ring_rc_priority::run_program::<
            Msb0,
            StatesRingRcFixedUniqueRing<ThreadRc, 50, 100>,
        >,
    );

    for (prog_name, prog) in progs.iter() {
        let mut group = c.benchmark_group(*prog_name);
        group.sample_size(20);
        for (engine_name, v) in engines.iter() {
            group.bench_with_input(
                BenchmarkId::new(*engine_name, 0),
                &(prog, *v),
                |b, (prog, engine)| b.iter(|| test_bench_helper(prog, *engine)),
            );
        }
    }

    // Another group of tests comparing different lookup types:

    let l = LookupType::MaskAndChoose {
        mask: BitVec::<u8, Msb0>::from_slice(&[0xffu8, 0x0, 0xff, 0x00]),
        choices: vec![InstructionEncoding {
            value: BitVec::<u8, Msb0>::from_slice(&[0xa2u8, 0x0, 0x55, 0x00]),
            operands: vec![],
            context: None,
        }],
    };
    let mut progs = HashMap::new();
    progs.insert(
        "Lookup",
        // Now lets make sure our pike method can handle even the bad case:
        Pattern::<Msb0> {
            steps: vec![
                Op::Lookup {
                    data: vec![l.clone()],
                },
                Op::Match { match_number: 0 },
            ],
            tables: vec![],
        },
    );
    progs.insert(
        "LookupQuick",
        // Now lets make sure our pike method can handle even the bad case:
        Pattern::<Msb0> {
            steps: vec![
                Op::LookupQuick {
                    bytes: vec![0xa2],
                    data: vec![l],
                },
                Op::Match { match_number: 0 },
            ],
            tables: vec![],
        },
    );

    let mut engines: EngineHash = HashMap::new();
    engines.insert(
        "StatesRingRcRing",
        pikevm_loop_ring_rc_priority::run_program::<Msb0, StatesRingRcRing<ThreadRc>>,
    );
    engines.insert(
        "StatesRingRcFixedUniqueRing",
        pikevm_loop_ring_rc_priority::run_program::<
            Msb0,
            StatesRingRcFixedUniqueRing<ThreadRc, 50, 100>,
        >,
    );

    // We have an extra "block" here so "group" is dropped at the end meaning we can use "c" as mutable again
    for (engine_name, engine) in engines.iter() {
        let mut group = c.benchmark_group(format!("Lookups_{}", *engine_name));
        for (prog_name, prog) in progs.iter() {
            group.bench_with_input(BenchmarkId::new(*prog_name, 0), prog, |b, prog| {
                b.iter(|| lookup_helper(prog, *engine))
            });
        }
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
