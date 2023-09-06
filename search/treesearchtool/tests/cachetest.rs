// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

#![feature(test)]

#[macro_use]
extern crate lazy_static;

use bitvec::prelude::*;
use std::fs;
use std::ops::Deref;
use std::path::PathBuf;
use treesearchlib::automata::states::StatesRingRcFixedRing;
use treesearchlib::automata::states::StatesRingRcFixedUnique;
use treesearchlib::automata::states::StatesRingRcRing;
use treesearchlib::automata::thread::ThreadRc;
use treesearchlib::b::AddressedBits;
use treesearchlib::bitstructs::instruction_encoding_aligned::InstructionEncodingAligned;
use treesearchlib::bitstructs::instruction_encoding_u32::InstructionEncodingu32;
use treesearchlib::bitstructs::InstructionEncoding;
use treesearchlib::bitstructs::LookupType;
extern crate test;
use test::Bencher;
use treesearchlib::automata::*;
use treesearchlib::b::Op;
use treesearchlib::b::Pattern as BitPattern;
use treesearchlib::j::Pattern;

fn get_test_dir_path() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests/");
    d
}

fn do_work(b: &mut Bencher, cache_size: usize) {
    let mut test_file = get_test_dir_path();
    test_file.push("./nastyPaternStartingWithAnybytesAndLoop.json");
    let pattern_data = fs::read(test_file.as_path()).unwrap();
    let pattern: Pattern = serde_json::from_slice(&pattern_data).unwrap();

    let bit_pattern: BitPattern<Msb0> = pattern.into();
    let mut program = BitPattern::get_dot_star();
    program.append(&BitPattern::get_save_start());
    program.append(&bit_pattern);
    program.append(&BitPattern::get_save(1));
    program.steps.push(Op::Match { match_number: 0 });

    let random_bytes: Vec<u8> = (0..100).map(|_| rand::random::<u8>()).collect();

    b.iter(|| pikevm::run_program(cache_size, &program, &random_bytes.as_slice().into()));
}
#[bench]
fn test_bad500(b: &mut Bencher) {
    do_work(b, 500);
}
#[bench]
fn test_bad5(b: &mut Bencher) {
    do_work(b, 5);
}
#[bench]
fn test_bad0(b: &mut Bencher) {
    do_work(b, 0);
}

fn load_ptn(file: &str) -> BitPattern<Msb0> {
    let mut test_file = get_test_dir_path();
    test_file.push(file);
    let pattern_data = fs::read(test_file.as_path()).unwrap();
    let pattern: Pattern = serde_json::from_slice(&pattern_data).unwrap();

    pattern.into()
}
fn test_file(
    b: &mut Bencher,
    file: &str,
    fn_to_test: fn(usize, &BitPattern<Msb0>, &AddressedBits) -> Results,
) {
    let bit_pattern = load_ptn(file);
    let mut program = BitPattern::get_dot_star();
    program.append(&BitPattern::get_save_start());
    program.append(&bit_pattern);
    program.append(&BitPattern::get_save(1));
    program.steps.push(Op::Match { match_number: 0 });

    let zero_bytes = vec![0u8; 1000];
    b.iter(|| fn_to_test(100, &program, &zero_bytes.as_slice().into()));
}

fn test_file_save_lots(
    b: &mut Bencher,
    file: &str,
    fn_to_test: fn(usize, &BitPattern<Msb0>, &AddressedBits) -> Results,
) {
    let bit_pattern = load_ptn(file);
    let mut program = BitPattern::get_dot_star();
    program.append(&BitPattern::get_save_start());
    program.append(&BitPattern::get_save(1));
    program.append(&BitPattern::get_save(2));
    program.append(&BitPattern::get_save(3));
    program.append(&BitPattern::get_save(4));
    program.append(&BitPattern::get_save(5));
    program.append(&BitPattern::get_save(6));
    program.append(&BitPattern::get_save(8));
    program.append(&BitPattern::get_save(9));
    program.append(&bit_pattern);
    program.append(&BitPattern::get_save(1));
    program.steps.push(Op::Match { match_number: 0 });

    let zero_bytes = vec![0u8; 1000];
    b.iter(|| fn_to_test(100, &program, &zero_bytes.as_slice().into()));
}

#[bench]
fn test_single_anys(b: &mut Bencher) {
    test_file(b, "./lotsOfAnysWithSplits.json", pikevm::run_program);
}

#[bench]
fn test_anybytesequences(b: &mut Bencher) {
    test_file(
        b,
        "./lotsOfAnysWithSplits_butInsteadUsingAnyByteSequence.json",
        pikevm::run_program,
    );
}
#[bench]
fn test_single_anys_ring(b: &mut Bencher) {
    test_file(b, "./lotsOfAnysWithSplits.json", pikevm_ring::run_program);
}

#[bench]
fn test_anybytesequences_ring(b: &mut Bencher) {
    test_file(
        b,
        "./lotsOfAnysWithSplits_butInsteadUsingAnyByteSequence.json",
        pikevm_ring::run_program,
    );
}

#[bench]
fn test_wild(b: &mut Bencher) {
    test_file(b, "./arm_CVE-2019-5436_WILD.json", pikevm::run_program);
}
#[bench]
fn test_more(b: &mut Bencher) {
    test_file(b, "./arm_CVE-2019-5436_MORE.json", pikevm::run_program);
}
#[bench]
fn test_wild_ring(b: &mut Bencher) {
    test_file(b, "./arm_CVE-2019-5436_WILD.json", pikevm_ring::run_program);
}
#[bench]
fn test_more_ring(b: &mut Bencher) {
    test_file(b, "./arm_CVE-2019-5436_MORE.json", pikevm_ring::run_program);
}

#[bench]
fn test_wild_loop(b: &mut Bencher) {
    test_file(b, "./arm_CVE-2019-5436_WILD.json", pikevm_loop::run_program);
}
#[bench]
fn test_more_loop(b: &mut Bencher) {
    test_file(b, "./arm_CVE-2019-5436_MORE.json", pikevm_loop::run_program);
}

#[bench]
fn test_wild_loop_ring(b: &mut Bencher) {
    test_file(
        b,
        "./arm_CVE-2019-5436_WILD.json",
        pikevm_loop_ring::run_program,
    );
}
#[bench]
fn test_more_loop_ring(b: &mut Bencher) {
    test_file(
        b,
        "./arm_CVE-2019-5436_MORE.json",
        pikevm_loop_ring::run_program,
    );
}

#[bench]
fn test_wild_loop_ring_aligned(b: &mut Bencher) {
    test_file(
        b,
        "./arm_CVE-2019-5436_WILD_aligned.json",
        pikevm_loop_ring::run_program,
    );
}
#[bench]
fn test_more_loop_ring_aligned(b: &mut Bencher) {
    test_file(
        b,
        "./arm_CVE-2019-5436_MORE_aligned.json",
        pikevm_loop_ring::run_program,
    );
}
#[bench]
fn test_wild_loop_ring_u32(b: &mut Bencher) {
    test_file(
        b,
        "./arm_CVE-2019-5436_WILD_u32.json",
        pikevm_loop_ring::run_program,
    );
}
#[bench]
fn test_more_loop_ring_u32(b: &mut Bencher) {
    test_file(
        b,
        "./arm_CVE-2019-5436_MORE_u32.json",
        pikevm_loop_ring::run_program,
    );
}

// #[bench]
// fn test_wild_loop_ring_rc(b: &mut Bencher) {
//     test_file(
//         b,
//         "./arm_CVE-2019-5436_WILD.json",
//         pikevm_loop_ring_rc::run_program,
//     );
// }
// #[bench]
// fn test_more_loop_ring_rc(b: &mut Bencher) {
//     test_file(
//         b,
//         "./arm_CVE-2019-5436_MORE.json",
//         pikevm_loop_ring_rc::run_program,
//     );
// }

// #[bench]
// fn test_wild_loop_ring_aligned_rc(b: &mut Bencher) {
//     test_file(
//         b,
//         "./arm_CVE-2019-5436_WILD_aligned.json",
//         pikevm_loop_ring_rc::run_program,
//     );
// }
// #[bench]
// fn test_more_loop_ring_aligned_rc(b: &mut Bencher) {
//     test_file(
//         b,
//         "./arm_CVE-2019-5436_MORE_aligned.json",
//         pikevm_loop_ring_rc::run_program,
//     );
// }
// #[bench]
// fn test_wild_loop_ring_u32_rc(b: &mut Bencher) {
//     test_file(
//         b,
//         "./arm_CVE-2019-5436_WILD_u32.json",
//         pikevm_loop_ring_rc::run_program,
//     );
// }
// #[bench]
// fn test_more_loop_ring_u32_rc(b: &mut Bencher) {
//     test_file(
//         b,
//         "./arm_CVE-2019-5436_MORE_u32.json",
//         pikevm_loop_ring_rc::run_program,
//     );
// }
#[bench]
fn test_more_loop_ring_fixed_u32_rc(b: &mut Bencher) {
    test_file(
        b,
        "./arm_CVE-2019-5436_MORE_u32.json",
        pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixedRing<ThreadRc, 10, 10>>,
    );
}
#[bench]
fn test_more_loop_ring_fixed_unique_u32_rc(b: &mut Bencher) {
    test_file(
        b,
        "./arm_CVE-2019-5436_MORE_u32.json",
        pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixedUnique<ThreadRc, 10, 10>>,
    );
}

#[bench]
fn test_wild_loop_ring_u32_save_lots(b: &mut Bencher) {
    test_file_save_lots(
        b,
        "./arm_CVE-2019-5436_MORE_u32.json",
        pikevm_loop_ring::run_program,
    );
}
#[bench]
fn test_wild_loop_ring_u32_save_lots_rc(b: &mut Bencher) {
    test_file_save_lots(
        b,
        "./arm_CVE-2019-5436_MORE_u32.json",
        pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcRing<ThreadRc>>,
    );
}
#[bench]
fn test_wild_loop_ring_fixed_u32_save_lots_rc(b: &mut Bencher) {
    test_file_save_lots(
        b,
        "./arm_CVE-2019-5436_MORE_u32.json",
        pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixedRing<ThreadRc, 10, 10>>,
    );
}
#[bench]
fn test_wild_loop_ring_fixed_unique_u32_save_lots_rc(b: &mut Bencher) {
    test_file_save_lots(
        b,
        "./arm_CVE-2019-5436_MORE_u32.json",
        pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixedUnique<ThreadRc, 10, 10>>,
    );
}
#[bench]
fn xor_naive(b: &mut Bencher) {
    let mask = BitVec::<_, Msb0>::from_slice(&[0x52u8, 0x96, 0x71, 0x41]);

    let subject_full = BitVec::<_, Msb0>::from_slice(&[0x11u8, 0x44, 0x12, 0x92]);

    b.iter(|| subject_full.clone() & mask.clone());
}
#[bench]
fn xor_tricky(b: &mut Bencher) {
    let mask = BitVec::<_, Msb0>::from_slice(&[0x52u8, 0x96, 0x71, 0x41]);

    let subject_full = BitVec::<_, Msb0>::from_slice(&[0x11u8, 0x44, 0x12, 0x92]);

    b.iter(|| -> BitVec<u8, Msb0> {
        let mut mask_iter = mask.iter();
        subject_full
            .iter()
            .map(|x| x.deref() & mask_iter.next().as_deref().unwrap())
            .collect()
    });
}

lazy_static! {
    pub static ref TEST_DATA: Vec<u8> = (0..5000).map(|_| rand::random::<u8>()).collect();
}
#[bench]
fn lookup_bitvec(b: &mut Bencher) {
    let l = LookupType::MaskAndChoose {
        mask: BitVec::<u8, Msb0>::from_slice(&[0xffu8, 0x0, 0xff, 0x00]),
        choices: vec![
            InstructionEncoding {
                value: BitVec::<u8, Msb0>::from_slice(&[0xa2u8, 0x0, 0x55, 0x00]),
                operands: vec![],
            },
            InstructionEncoding {
                value: BitVec::<u8, Msb0>::from_slice(&[0x77u8, 0x02, 0x54, 0x01]),
                operands: vec![],
            },
            InstructionEncoding {
                value: BitVec::<u8, Msb0>::from_slice(&[0xb3u8, 0x10, 0x30, 0x70]),
                operands: vec![],
            },
        ],
    };
    // The following is kinda sorta like the following pseudo-regex:
    // \x03\x04(\x05?\x06).\x09%INSTRUCTION%
    let prog = BitPattern::<Msb0> {
        steps: vec![Op::Lookup { data: vec![l] }, Op::Match { match_number: 0 }],
        tables: vec![],
    };
    b.iter(|| pikevm::run_program(10, &prog, &TEST_DATA.as_slice().into()));
}

#[bench]
fn lookup_aligned(b: &mut Bencher) {
    let l = LookupType::MaskAndChooseAligned {
        mask: vec![0xffu8, 0x0, 0xff, 0x00],
        choices: vec![
            InstructionEncodingAligned {
                value: vec![0xa2u8, 0x0, 0x55, 0x00],
                operands: vec![],
            },
            InstructionEncodingAligned {
                value: vec![0x77u8, 0x02, 0x54, 0x01],
                operands: vec![],
            },
            InstructionEncodingAligned {
                value: vec![0xb3u8, 0x10, 0x30, 0x70],
                operands: vec![],
            },
        ],
    };
    // The following is kinda sorta like the following pseudo-regex:
    // \x03\x04(\x05?\x06).\x09%INSTRUCTION%
    let prog = BitPattern::<Msb0> {
        steps: vec![Op::Lookup { data: vec![l] }, Op::Match { match_number: 0 }],
        tables: vec![],
    };
    b.iter(|| pikevm::run_program(10, &prog, &TEST_DATA.as_slice().into()));
}

#[bench]
fn lookup_u32(b: &mut Bencher) {
    let l = LookupType::MaskAndChooseu32 {
        mask: 0xFF00FF00,
        choices: vec![
            InstructionEncodingu32 {
                value: 0xa2005500,
                operands: vec![],
            },
            InstructionEncodingu32 {
                value: 0x77025401,
                operands: vec![],
            },
            InstructionEncodingu32 {
                value: 0xb3103070,
                operands: vec![],
            },
        ],
    };
    // The following is kinda sorta like the following pseudo-regex:
    // \x03\x04(\x05?\x06).\x09%INSTRUCTION%
    let prog = BitPattern::<Msb0> {
        steps: vec![Op::Lookup { data: vec![l] }, Op::Match { match_number: 0 }],
        tables: vec![],
    };
    b.iter(|| pikevm::run_program(10, &prog, &TEST_DATA.as_slice().into()));
}
