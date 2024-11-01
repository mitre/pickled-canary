//! Much of this module is inspired by the first two main articles found here:
//! https://swtch.com/~rsc/regexp/
//!
//! Most of the public modules (except for [thread] and [results]) in this
//! module are different implementations of the our NFA engines. They *should*
//! all be functionally equavalent, but they each have different performance
//! characteristics. In every case, the "main" function for each is
//! "run_program". The most performant of these modules (currently
//! [pikevm_loop_ring_rc]) is re-exported at the top level of this module for
//! easy calling (and easy updating if an improved version is made).
//!
//! See the module-level documentation in each of the sub-crates for a brief
//! description of it's implementation. It is suggested to start with the
//! simplest ([recursive_backtracking]) and work up in complexity from there.

// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

extern crate test;

mod results;
pub mod thread;
pub use results::*;
pub mod states;

pub mod pikevm;
pub mod pikevm_loop;
pub mod pikevm_loop_ring;
pub mod pikevm_loop_ring_rc;
pub mod pikevm_loop_ring_rc_priority;
pub mod pikevm_ring;
pub mod recursive_backtracking;
pub mod recursive_backtracking_loop;

pub use pikevm_loop_ring_rc_priority::run_program;

#[cfg(test)]
mod tests {

    use crate::bitstructs::{AddressedBits, InstructionEncoding, LookupType, Op, Pattern};
    use bitvec::prelude::*;

    use super::{
        states::{
            StatesRingRc, StatesRingRcFixed, StatesRingRcFixedRing, StatesRingRcFixedUnique,
            StatesRingRcRing,
        },
        thread::ThreadRc,
        *,
    };

    #[test]
    fn test_all() {
        let l = LookupType::MaskAndChoose {
            mask: BitVec::<u8, Msb0>::from_slice(&[0xffu8, 0x0, 0xff, 0x00]),
            choices: vec![InstructionEncoding {
                value: BitVec::<u8, Msb0>::from_slice(&[0xa2u8, 0x0, 0x55, 0x00]),
                operands: vec![],
            }],
        };
        // The following is kinda sorta like the following pseudo-regex:
        // \x03\x04(\x05?\x06).\x09%INSTRUCTION%
        let prog = Pattern::<Msb0> {
            steps: vec![
                Op::Byte { value: 0x3 },
                Op::MaskedByte {
                    mask: 0x0F,
                    value: 0x4,
                },
                Op::SaveStart,
                Op::Split { dest1: 4, dest2: 6 },
                Op::Byte { value: 0x5 },
                Op::Jmp { dest: 6 },
                // #6
                Op::Byte { value: 0x6 },
                Op::Save { slot: 1 },
                Op::AnyByte,
                Op::Byte { value: 0x9 },
                Op::LookupQuick {
                    bytes: vec![0xa2],
                    data: vec![l],
                },
                // #11
                Op::AnyByteSequence {
                    min: 2,
                    max: 4,
                    interval: 1,
                },
                Op::Byte { value: 0x33 },
                Op::AnyByteSequence {
                    min: 2,
                    max: 2,
                    interval: 1,
                },
                Op::Match { match_number: 0 },
            ],
            tables: vec![],
        };

        for method in [
            pikevm::run_program,
            pikevm_ring::run_program,
            pikevm_loop::run_program,
            pikevm_loop_ring::run_program,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRc<ThreadRc>>,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixed<ThreadRc, 10, 10>>,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixedUnique<ThreadRc, 10, 10>>,
            pikevm_loop_ring_rc_priority::run_program::<Msb0, StatesRingRcRing<ThreadRc>>,
            pikevm_loop_ring_rc_priority::run_program::<
                Msb0,
                StatesRingRcFixedRing<ThreadRc, 10, 10>,
            >,
            recursive_backtracking::run_program,
            recursive_backtracking_loop::run_program,
        ] {
            let input = [
                3, 0x74, 5, 6, 0x22, 9, 0xa2u8, 0x77, 0x55, 0x12, 1, 2, 3, 0x33, 1, 2,
            ]
            .as_slice();
            let results = method(10, &prog, &input.into());
            assert!(results.matched);
            assert!(results.saved.is_some());
            let saved_results = results.saved.unwrap();
            assert_eq!(saved_results.start.unwrap(), 2);
            assert_eq!(*saved_results.captures.get(&1).unwrap(), 4);

            let input = [3, 4, 6, 2, 9, 0xa2u8, 0x77, 0x55, 0x12, 1, 2, 3, 0x33, 1, 2].as_slice();
            let results = method(10, &prog, &input.into());
            assert!(results.matched);
            assert!(results.saved.is_some());
            let saved_results = results.saved.unwrap();
            assert_eq!(saved_results.start.unwrap(), 2);
            assert_eq!(*saved_results.captures.get(&1).unwrap(), 3);

            // This is the same as the previous, but without the extra bytes at
            // the end (so the AnyBytesSequence isn't satisified)
            let input = [3, 4, 6, 2, 9, 0xa2u8, 0x77, 0x55, 0x12].as_slice();
            let results = method(10, &prog, &input.into());
            assert!(!results.matched);

            // This is the same as the previous success, but a messed up MaskedByte
            let input = [3, 3, 6, 2, 9, 0xa2u8, 0x77, 0x55, 0x12, 1, 2, 3, 0x33, 1, 2].as_slice();
            let results = method(10, &prog, &input.into());
            assert!(!results.matched);

            let input = [3, 4, 7, 4, 9].as_slice();
            let results = method(10, &prog, &input.into());
            assert!(!results.matched);

            // This should fail because of the lookup step
            let input = [3, 4, 6, 2, 9, 0x00, 0x77, 0x55, 0x12, 1, 2, 3, 0x33, 1, 2].as_slice();
            let results = method(10, &prog, &input.into());
            assert!(!results.matched);
        }
    }

    #[test]
    fn test_order() {
        let prog = Pattern::<Msb0> {
            steps: vec![
                Op::Split { dest1: 1, dest2: 4 },
                Op::SaveStart,
                Op::AnyByte,
                Op::Jmp { dest: 6 },
                Op::Save { slot: 1 },
                Op::Byte { value: 0x5 },
                Op::Match { match_number: 0 },
            ],
            tables: vec![],
        };

        for method in [
            pikevm::run_program,
            pikevm_ring::run_program,
            pikevm_loop::run_program,
            pikevm_loop_ring::run_program,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRc<ThreadRc>>,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixed<ThreadRc, 10, 10>>,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixedUnique<ThreadRc, 10, 10>>,
            pikevm_loop_ring_rc_priority::run_program::<
                Msb0,
                StatesRingRcFixedRing<ThreadRc, 10, 10>,
            >,
            recursive_backtracking::run_program,
            recursive_backtracking_loop::run_program,
        ] {
            let input = [5, 3].as_slice();
            let results = method(10, &prog, &input.into());
            assert!(results.matched);
            assert!(results.saved.is_some());
            let saved_results = results.saved.unwrap();

            eprintln!("{:?}", saved_results);
            assert_eq!(saved_results.start.unwrap(), 0);
            assert!(!saved_results.captures.contains_key(&1));
        }
    }

    /// This test makes sure that save values are "unsaved" if a branch is
    /// explored but doesn't actually match. The pattern in this test will take
    /// a branch, explore it, and in the process of exploring it save a value.
    /// This branch will not end in match, but the second arm of the branch
    /// will. However, this second arm should NOT have the saved value from the
    /// first branch which was unsuccessfully explored.
    ///
    /// This test demonstrates that our recursive_backtracking automata don't
    /// get state quite right in the case there are splits with matches inside.
    /// Uncomment the two commented out lines in this test to show the failure.
    #[test]
    fn test_order2() {
        let prog = Pattern::<Msb0> {
            steps: vec![
                Op::Split { dest1: 1, dest2: 4 },
                Op::Save { slot: 0 },
                Op::Byte { value: 0x5 },
                Op::Jmp { dest: 6 },
                // #4
                Op::Save { slot: 1 },
                Op::AnyByte,
                // #6
                Op::Match { match_number: 0 },
            ],
            tables: vec![],
        };

        for method in [
            pikevm::run_program,
            pikevm_ring::run_program,
            pikevm_loop::run_program,
            pikevm_loop_ring::run_program,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRc<ThreadRc>>,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixed<ThreadRc, 10, 10>>,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixedUnique<ThreadRc, 10, 10>>,
            pikevm_loop_ring_rc_priority::run_program::<
                Msb0,
                StatesRingRcFixedRing<ThreadRc, 10, 10>,
            >,
            // recursive_backtracking::run_program,
            // recursive_backtracking_loop::run_program,
        ] {
            let input = [7, 3].as_slice();
            let results = method(10, &prog, &input.into());
            assert!(results.matched);
            assert!(results.saved.is_some());
            let saved_results = results.saved.unwrap();
            // eprintln!("{:?}", saved_results);
            assert!(!saved_results.captures.contains_key(&0));
            assert_eq!(*saved_results.captures.get(&1).unwrap(), 0);
        }
    }

    #[test]
    fn test_dot_star() {
        let mut prog = Pattern::<Msb0>::get_dot_star();
        prog.append(&Pattern::<Msb0>::get_save_start());
        prog.append(&Pattern::<Msb0> {
            steps: vec![Op::Byte { value: 0x5 }, Op::Match { match_number: 0 }],
            tables: vec![],
        });

        for method in [
            pikevm::run_program,
            pikevm_ring::run_program,
            pikevm_loop::run_program,
            pikevm_loop_ring::run_program,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRc<ThreadRc>>,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixed<ThreadRc, 10, 10>>,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixedUnique<ThreadRc, 10, 10>>,
            pikevm_loop_ring_rc_priority::run_program::<
                Msb0,
                StatesRingRcFixedRing<ThreadRc, 10, 10>,
            >,
            recursive_backtracking::run_program,
            recursive_backtracking_loop::run_program,
        ] {
            let input = [4, 4, 4, 4, 5, 5, 0].as_slice();
            let results = method(10, &prog, &input.into());
            assert!(results.matched);
            assert!(results.saved.is_some());
            let saved_results = results.saved.unwrap();
            // Make sure we match the first 5, not the second one
            assert_eq!(saved_results.start.unwrap(), 4);
            assert!(!saved_results.captures.contains_key(&1));
        }
    }

    #[test]
    fn test_negative_lookahead() {
        let prog = Pattern::<Msb0> {
            steps: vec![
                Op::Byte { value: 0x5 },
                Op::NegativeLookahead {
                    pattern: Pattern::<Msb0> {
                        steps: vec![Op::Byte { value: 0x7 }, Op::Match { match_number: 0 }],
                        tables: vec![],
                    },
                },
                Op::Match { match_number: 0 },
            ],
            tables: vec![],
        };

        for method in [
            pikevm::run_program,
            pikevm_ring::run_program,
            pikevm_loop::run_program,
            pikevm_loop_ring::run_program,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRc<ThreadRc>>,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixed<ThreadRc, 10, 10>>,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixedUnique<ThreadRc, 10, 10>>,
            pikevm_loop_ring_rc_priority::run_program::<
                Msb0,
                StatesRingRcFixedRing<ThreadRc, 10, 10>,
            >,
            recursive_backtracking::run_program,
            recursive_backtracking_loop::run_program,
        ] {
            let input = [5, 3].as_slice();
            let results = method(10, &prog, &input.into());
            assert!(results.matched);

            let input = [5, 7].as_slice();
            let results = method(10, &prog, &input.into());
            assert!(!results.matched);
        }
    }

    #[test]
    fn test_splitmulti() {
        let prog = Pattern::<Msb0> {
            steps: vec![
                Op::SplitMulti {
                    dests: vec![1, 3, 5, 7, 9],
                },
                Op::Byte { value: 0x5 },
                Op::Match { match_number: 0 },
                Op::Byte { value: 0x8 },
                Op::Match { match_number: 1 },
                Op::AnyByte,
                Op::Match { match_number: 2 },
                Op::AnyByte,
                Op::Match { match_number: 3 },
                Op::Byte { value: 0x9 },
                Op::Match { match_number: 4 },
            ],
            tables: vec![],
        };

        // Only the states which use inner ring buffers work with this test case!
        let mut count = 0;
        for method in [
            // pikevm::run_program,
            // pikevm_ring::run_program,
            // pikevm_loop::run_program,
            // pikevm_loop_ring::run_program,
            // pikevm_loop_ring_rc::run_program,
            // pikevm_loop_ring_rc_fixed::run_program::<Msb0, 10, 10>,
            // pikevm_loop_ring_rc_fixed_unique::run_program::<Msb0, 10, 10>,
            pikevm_loop_ring_rc_priority::run_program::<Msb0, StatesRingRcRing<ThreadRc>>,
            pikevm_loop_ring_rc_priority::run_program::<
                Msb0,
                StatesRingRcFixedRing<ThreadRc, 10, 10>,
            >,
            // recursive_backtracking::run_program,
            // recursive_backtracking_loop::run_program,
        ] {
            count += 1;
            let input = [5, 3].as_slice();
            let results = method(10, &prog, &input.into());
            assert!(results.matched);
            assert_eq!(results.match_number.unwrap(), 0, "Count is: {}", count);

            let input = [8, 3].as_slice();
            let results = method(10, &prog, &input.into());
            assert!(results.matched);
            assert_eq!(results.match_number.unwrap(), 1);

            let input = [3, 3].as_slice();
            let results = method(10, &prog, &input.into());
            assert!(results.matched);
            assert_eq!(results.match_number.unwrap(), 2);
        }
    }

    #[test]
    fn test_splitmulti2() {
        let prog = Pattern::<Msb0> {
            steps: vec![
                Op::SplitMulti {
                    dests: vec![1, 4, 7, 10, 13],
                },
                // #1
                Op::Byte { value: 0x5 },
                Op::Byte { value: 0x5 },
                Op::Match { match_number: 0 },
                // #4
                Op::Byte { value: 0x8 },
                Op::Byte { value: 0x8 },
                Op::Match { match_number: 1 },
                // #7
                Op::AnyByte,
                Op::AnyByte,
                Op::Match { match_number: 2 },
                // #10
                Op::AnyByte,
                Op::AnyByte,
                Op::Match { match_number: 3 },
                // #13
                Op::Byte { value: 0x9 },
                Op::Byte { value: 0x9 },
                Op::Match { match_number: 4 },
            ],
            tables: vec![],
        };

        // Only State storage using inner ring buffers work for this test
        let mut count = 0;
        for method in [
            // pikevm::run_program,
            // pikevm_ring::run_program,
            // pikevm_loop::run_program,
            // pikevm_loop_ring::run_program,
            // pikevm_loop_ring_rc::run_program,
            // pikevm_loop_ring_rc_fixed::run_program::<Msb0, 10, 10>,
            // pikevm_loop_ring_rc_fixed_unique::run_program::<Msb0, 10, 10>,
            pikevm_loop_ring_rc_priority::run_program::<Msb0, StatesRingRcRing<ThreadRc>>,
            pikevm_loop_ring_rc_priority::run_program::<
                Msb0,
                StatesRingRcFixedRing<ThreadRc, 10, 50>,
            >,
            // recursive_backtracking::run_program,
            // recursive_backtracking_loop::run_program,
        ] {
            count += 1;
            let input = [5, 5, 3, 3].as_slice();
            let results = method(10, &prog, &input.into());
            assert!(results.matched);
            assert_eq!(results.match_number.unwrap(), 0, "Count is: {}", count);

            let input = [8, 8, 3].as_slice();
            let results = method(10, &prog, &input.into());
            assert!(results.matched);
            assert_eq!(results.match_number.unwrap(), 1);

            let input = [3, 3].as_slice();
            let results = method(10, &prog, &input.into());
            assert!(results.matched);
            assert_eq!(results.match_number.unwrap(), 2);
        }
    }

    #[test]
    fn test_splitordering() {
        let prog = Pattern::<Msb0> {
            steps: vec![
                Op::Split { dest1: 1, dest2: 7 },
                Op::AnyByte, // 0xa
                // #2
                Op::Split { dest1: 3, dest2: 5 },
                Op::Byte { value: 0x7 }, // 0xb
                Op::Match { match_number: 0 },
                Op::AnyByte, // 0xc
                Op::Match { match_number: 1 },
                // #7
                Op::Byte { value: 0xd },
                Op::Split {
                    dest1: 9,
                    dest2: 11,
                },
                Op::AnyByte, // 0xe
                Op::Match { match_number: 2 },
                Op::AnyByte, // 0xf
                Op::Match { match_number: 3 },
            ],
            tables: vec![],
        };

        let mut count = 0;
        for method in [
            pikevm::run_program,
            pikevm_ring::run_program,
            pikevm_loop::run_program,
            pikevm_loop_ring::run_program,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRc<ThreadRc>>,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixed<ThreadRc, 10, 10>>,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixedUnique<ThreadRc, 10, 10>>,
            pikevm_loop_ring_rc_priority::run_program::<Msb0, StatesRingRcRing<ThreadRc>>,
            pikevm_loop_ring_rc_priority::run_program::<
                Msb0,
                StatesRingRcFixedRing<ThreadRc, 10, 10>,
            >,
            // recursive_backtracking::run_program,
            // recursive_backtracking_loop::run_program,
        ] {
            count += 1;
            let input = [5, 3].as_slice();
            let results = method(10, &prog, &input.into());
            assert!(results.matched);
            assert_eq!(results.match_number.unwrap(), 1, "Count is: {}", count);
        }
    }
    #[test]
    fn test_splitordering_shallow() {
        let prog = Pattern::<Msb0> {
            steps: vec![
                Op::Split { dest1: 1, dest2: 3 },
                Op::AnyByte, // 0xa
                Op::Match { match_number: 0 },
                Op::AnyByte, // 0xb
                Op::Match { match_number: 1 },
            ],
            tables: vec![],
        };

        let mut count = 0;
        for method in [
            pikevm::run_program,
            pikevm_ring::run_program,
            pikevm_loop::run_program,
            pikevm_loop_ring::run_program,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRc<ThreadRc>>,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixed<ThreadRc, 10, 10>>,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixedUnique<ThreadRc, 10, 10>>,
            pikevm_loop_ring_rc_priority::run_program::<Msb0, StatesRingRcRing<ThreadRc>>,
            pikevm_loop_ring_rc_priority::run_program::<
                Msb0,
                StatesRingRcFixedRing<ThreadRc, 10, 10>,
            >,
            // recursive_backtracking::run_program,
            // recursive_backtracking_loop::run_program,
        ] {
            count += 1;
            let input = [5, 3].as_slice();
            let results = method(10, &prog, &input.into());
            assert!(results.matched);
            assert_eq!(results.match_number.unwrap(), 0, "Count is: {}", count);
        }
    }

    #[test]
    /// This test makes sure we don't populate labels in OR "arms" that we
    /// didn't actually take as part of our match
    fn test_or_label_order() {
        let prog_json: j::Pattern = serde_json::from_str(
            r##"{"tables":[],"steps":[{
                "type": "BYTE",
                "value": 0
            },
            {
                "note": "AnyBytesNode Start: 1 End: 4 Interval: 1 From: Token from line #2: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{1,4}`",
                "min": 1,
                "max": 4,
                "interval": 1,
                "type": "ANYBYTESEQUENCE"
            },
            {
                "dest2": 6,
                "type": "SPLIT",
                "dest1": 3
            },
            {
                "type": "LABEL",
                "value": "Label1"
            },
            {
                "type": "BYTE",
                "value": 1
            },
            {
                "type": "JMP",
                "dest": 8
            },
            {
                "type": "LABEL",
                "value": "Label2"
            },
            {
                "type": "BYTE",
                "value": 2
            }],"compile_info":[{"compiled_using_binary":[{"path":["unknown"],"compiled_at_address":["01008420"],"md5":["unknown"]}],"language_id":["ARM:LE:32:v8"]}],"pattern_metadata":{}}"##,
        ).unwrap();

        let mut prog: Pattern<Msb0> = prog_json.into();
        prog.append(&Pattern::<Msb0> {
            steps: vec![Op::Match { match_number: 0 }],
            tables: vec![],
        });

        let mut count = 0;
        for method in [
            pikevm::run_program,
            pikevm_ring::run_program,
            pikevm_loop::run_program,
            pikevm_loop_ring::run_program,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRc<ThreadRc>>,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixed<ThreadRc, 50, 50>>,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixedUnique<ThreadRc, 50, 50>>,
            pikevm_loop_ring_rc_priority::run_program::<Msb0, StatesRingRcRing<ThreadRc>>,
            pikevm_loop_ring_rc_priority::run_program::<
                Msb0,
                StatesRingRcFixedRing<ThreadRc, 50, 50>,
            >,
            // recursive_backtracking::run_program,
            // recursive_backtracking_loop::run_program,
        ] {
            count += 1;
            let input = [0, 7, 7, 1].as_slice();
            let results = method(10, &prog, &input.into());
            // eprintln!("Results: {:?}", results);
            assert!(results.matched);
            assert_eq!(results.match_number.unwrap(), 0, "Count is: {}", count);

            let saved = results.saved.unwrap();
            // Ensure only one label is populated
            assert_eq!(saved.labels.len(), 1, "Count is: {}", count);
            // Ensure that label is "Label1"
            assert_eq!(
                saved.labels.get("Label1").unwrap().to_owned(),
                3,
                "Count is: {}",
                count
            );
        }
    }

    // #[test]
    // fn test_lots_of_recursion() {
    //     let prog = Pattern::<Msb0> {
    //         steps: vec![
    //             Op::AnyByte,
    //             // It's VERY important that the first option here is the one
    //             // which will fail more quickly. Otherwise, we quickly run out
    //             // of stack
    //             Op::Split { dest1: 2, dest2: 0 },
    //             Op::Byte { value: 0x3 },
    //             Op::Byte { value: 0x4 },
    //             Op::Match { match_number: 0 },
    //         ],
    //         tables: vec![],
    //     };
    //     for method in [
    //         pikevm::run_program,
    //         recursive_backtracking::run_program,
    //         recursive_backtracking_loop::run_program,
    //     ] {
    //         let mut input = vec![0; 400];
    //         input.push(0x3);
    //         input.push(0x4);
    //         let results = method(10, &prog, &input);
    //         assert!(results.matched);
    //     }

    //     // Now lets make sure our pike method can handle even the bad case:
    //     let prog = Pattern::<Msb0> {
    //         steps: vec![
    //             Op::AnyByte,
    //             // This the *bad* way! It'll blow up the recursive methods
    //             Op::Split { dest1: 0, dest2: 2 },
    //             Op::Byte { value: 0x3 },
    //             Op::Byte { value: 0x4 },
    //             Op::Match { match_number: 0 },
    //         ],
    //         tables: vec![],
    //     };

    //     // Adding the recursive options here will cause a caught-by-rust stack overflow
    //     for method in [pikevm::run_program] {
    //         let mut input = vec![0; 5000];
    //         input.push(0x3);
    //         input.push(0x4);
    //         let results = method(10, &prog, &input);
    //         assert!(results.matched);
    //     }
    // }

    #[test]
    fn test_lots_of_splits_actually_works() {
        let real_prog = Pattern::<Msb0> {
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
        };
        let mut prog = Pattern::<Msb0>::get_dot_star();
        prog.append(&real_prog);
        let mut input = vec![0; 50000];
        input.push(0x3);
        assert!(
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixedUnique<ThreadRc, 50, 50>>(
                10,
                &prog,
                &input.as_slice().into()
            )
            .matched
        );
        assert!(
            pikevm_loop_ring_rc_priority::run_program::<
                Msb0,
                StatesRingRcFixedRing<ThreadRc, 50, 50>,
            >(10, &prog, &input.as_slice().into())
            .matched
        );
    }

    #[test]
    fn test_anybytesequence_works() {
        let mut interv;
        let min_window = 10;
        for j in 1..5 {
            interv = j;
            let prog = Pattern::<Msb0> {
                steps: vec![
                    Op::AnyByteSequence {
                        min: min_window,
                        max: 20,
                        interval: interv,
                    },
                    Op::Byte { value: 0x3 },
                    Op::Match { match_number: 0 },
                ],
                tables: vec![],
            };

            for method in [
                pikevm::run_program,
                pikevm_ring::run_program,
                pikevm_loop::run_program,
                pikevm_loop_ring::run_program,
                pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRc<ThreadRc>>,
                pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixed<ThreadRc, 50, 10>>,
                pikevm_loop_ring_rc_priority::run_program::<
                    Msb0,
                    StatesRingRcFixedRing<ThreadRc, 50, 50>,
                >,
                // recursive_backtracking::run_program,
                // recursive_backtracking_loop::run_program,
            ] {
                // testing if it detects when interval in range
                for i in 0..30 {
                    let mut input = vec![0; i];
                    input.push(3);
                    let results = method(10, &prog, &input.as_slice().into());

                    if !(i >= min_window && i <= 20 && (i - min_window) % interv == 0) {
                        assert!(
                            !results.matched,
                            "Interval: {}, Shouldn't have matched with i={}",
                            interv, i
                        );
                    } else {
                        assert!(
                            results.matched,
                            "Interval: {}, Should have matched with i={}",
                            interv, i
                        );
                    }
                }
            }
        }
    }

    use crate::jsonstructs as j;

    fn expression_tester_helper(
        mut prog: Pattern<Msb0>,
        input_bytes: &AddressedBits,
        foo_value: i128,
    ) {
        prog.steps.push(Op::Match { match_number: 1 });

        for method in [
            pikevm::run_program,
            pikevm_ring::run_program,
            pikevm_loop::run_program,
            pikevm_loop_ring::run_program,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRc<ThreadRc>>,
            pikevm_loop_ring_rc::run_program::<Msb0, StatesRingRcFixed<ThreadRc, 50, 10>>,
            pikevm_loop_ring_rc_priority::run_program::<
                Msb0,
                StatesRingRcFixedRing<ThreadRc, 50, 50>,
            >,
            // recursive_backtracking::run_program,
            // recursive_backtracking_loop::run_program,
        ] {
            let results = method(10, &prog, input_bytes);
            assert!(results.matched, "Should have matched!");
            assert!(results.saved.is_some(), "Should have some saved data");
            let saved = results.saved.unwrap();
            assert!(
                saved.labels.contains_key("foo"),
                "Should have a label 'foo'"
            );
            assert_eq!(*saved.labels.get("foo").unwrap(), foo_value);
        }
    }

    #[test]
    fn test_expression_works_bl() {
        let prog_json: j::Pattern = serde_json::from_str(
            r##"{"tables":[],"steps":[{"type":"LABEL","value":"foo"},{"note":"AnyBytesNode Start: 12 End: 12 From: Token from line #2: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{12,12}`","min":12,"max":12,"type":"ANYBYTESEQUENCE"},{"data":[{"type":"MaskAndChoose","choices":[{"operands":[{"expression":{"op":"Add","children":{"left":{"op":"Add","children":{"left":{"op":"EndInstructionValue"},"right":{"op":"ConstantValue","value":4}}},"right":{"op":"Mult","children":{"left":{"op":"ConstantValue","value":4},"right":{"op":"OperandValue","offset":0,"child":{"op":"TokenField","value":{"bitend":23,"shift":0,"signbit":true,"bitstart":0,"byteend":2,"bigendian":false,"bytestart":0}}}}}}},"var_id":":foo","type":"Scalar","mask":[0,0,0,0]}],"value":[255,255,255,235]}],"mask":[255,255,255,255]},{"type":"MaskAndChoose","choices":[{"operands":[{"expression":{"op":"Add","children":{"left":{"op":"Add","children":{"left":{"op":"EndInstructionValue"},"right":{"op":"ConstantValue","value":4}}},"right":{"op":"Mult","children":{"left":{"op":"ConstantValue","value":4},"right":{"op":"OperandValue","offset":0,"child":{"op":"TokenField","value":{"bitend":23,"shift":0,"signbit":true,"bitstart":0,"byteend":2,"bigendian":false,"bytestart":0}}}}}}},"var_id":":foo","type":"Scalar","mask":[255,255,255,0]}],"value":[0,0,0,235]}],"mask":[0,0,0,255]}],"type":"LOOKUP"},{"note":"AnyBytesNode Start: 1 End: 1 From: Token from line #4: Token type: PICKLED_CANARY_COMMAND data: `ANY_BYTES{1,1}`","min":1,"max":1,"type":"ANYBYTESEQUENCE"}],"compile_info":[{"compiled_using_binary":[{"path":["unknown"],"compiled_at_address":["01008420"],"md5":["unknown"]}],"language_id":["ARM:LE:32:v8"]}],"pattern_metadata":{}}"##,
        ).unwrap();

        // the following is:
        // foo:
        // mov r0,r0
        // mov r0,r0
        // mov r0,r0
        // bl foo
        // mov r0,r0
        let input_bytes = [
            0x00u8, 0x00, 0xa0, 0xe1, 0x00, 0x00, 0xa0, 0xe1, 0x00, 0x00, 0xa0, 0xe1, 0xfb, 0xff,
            0xff, 0xeb, 0x00, 0x00, 0xa0, 0xe1,
        ];

        expression_tester_helper(prog_json.into(), &input_bytes.as_slice().into(), 0);
    }

    #[test]
    fn test_any_bytes_sequence_default() {
        let prog_json: j::Pattern = serde_json::from_str(
            r##"{"tables":[],"steps":[{"type":"ANYBYTESEQUENCE","min":7, "max":13}]}"##,
        )
        .unwrap();

        let real_prog = Pattern::<Msb0> {
            steps: vec![Op::AnyByteSequence {
                min: 7,
                max: 13,
                interval: 1,
            }],
            tables: vec![],
        };

        let converted_prog: Pattern<Msb0> = prog_json.into(); // converting json into bitstruct using from method
        assert_eq!(
            converted_prog, real_prog,
            "Expected JSON to match Bitstruct pattern"
        );
    }

    #[test]
    fn test_expression_works_ldr() {
        let prog_json: j::Pattern = serde_json::from_str(
            r##"{"tables":[],"steps":[{"data":[{"type":"MaskAndChoose","choices":[{"operands":[{"expression":{"op":"Sub","children":{"left":{"op":"Add","children":{"left":{"op":"StartInstructionValue"},"right":{"op":"ConstantValue","value":8}}},"right":{"op":"OperandValue","offset":0,"child":{"op":"TokenField","value":{"bitend":11,"shift":0,"signbit":false,"bitstart":0,"byteend":1,"bigendian":false,"bytestart":0}}}}},"var_id":":foo","type":"Scalar","mask":[255,15,0,0]}],"value":[0,48,31,229]},{"operands":[{"expression":{"op":"Add","children":{"left":{"op":"Add","children":{"left":{"op":"StartInstructionValue"},"right":{"op":"ConstantValue","value":8}}},"right":{"op":"OperandValue","offset":0,"child":{"op":"TokenField","value":{"bitend":11,"shift":0,"signbit":false,"bitstart":0,"byteend":1,"bigendian":false,"bytestart":0}}}}},"var_id":":foo","type":"Scalar","mask":[255,15,0,0]}],"value":[0,48,159,229]}],"mask":[0,240,255,255]}],"type":"LOOKUP"}],"compile_info":[{"compiled_using_binary":[{"path":["unknown"],"compiled_at_address":["01008420"],"md5":["unknown"]}],"language_id":["ARM:LE:32:v8"]}],"pattern_metadata":{}}"##,
        ).unwrap();

        // the following is:
        // ldr r3,[pc,#4]
        // mov r0,r0
        // mov r0,r0
        // mov r0,r0 // <--- ldr points here
        // mov r0,r0
        let input_bytes = [
            0x04u8, 0x30, 0x9f, 0xe5, 0x00, 0x00, 0xa0, 0xe1, 0x00, 0x00, 0xa0, 0xe1, 0x00, 0x00,
            0xa0, 0xe1, 0x00, 0x00, 0xa0, 0xe1,
        ];

        expression_tester_helper(prog_json.into(), &input_bytes.as_slice().into(), 0x0c);
    }
}
