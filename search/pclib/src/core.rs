// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

use bitvec::prelude::*;
use memmap2::MmapOptions;
use std::convert::TryInto;
use std::fs;
use std::fs::File;
use std::path::PathBuf;
use treesearchlib::automata::thread::ThreadRc;
use treesearchlib::automata::*;
use treesearchlib::b::Op;
use treesearchlib::b::Pattern as BitPattern;
use treesearchlib::bitstructs::AddressedBits;
use treesearchlib::bitstructs::LookupCache;
use treesearchlib::j::Pattern;

pub fn load_pattern_raw<Endian: BitOrder + Clone + std::fmt::Debug + PartialEq>(
    path: Option<&PathBuf>,
    pattern_file_path: &str,
    quiet_level: u64,
) -> BitPattern<Endian> {
    let p = match path {
        None => PathBuf::from(pattern_file_path),
        Some(x) => {
            let mut cloned_path = x.clone();
            cloned_path.push(pattern_file_path);
            cloned_path
        }
    };

    let pattern_data = fs::read(p).unwrap();
    load_pattern_from_data(&pattern_data, quiet_level)
}

pub fn load_pattern_from_data<Endian: BitOrder + Clone + std::fmt::Debug + PartialEq>(
    pattern_data: &[u8],
    quiet_level: u64,
) -> BitPattern<Endian> {
    let pattern: Pattern = serde_json::from_slice(pattern_data).unwrap();

    if quiet_level == 0 {
        eprintln!("Pattern: {:#?}", pattern);
    }
    let bit_pattern: BitPattern<Endian> = pattern.into();
    if quiet_level == 0 {
        eprintln!("Pattern: {:#?}", bit_pattern);
    }
    bit_pattern
}

pub fn load_pattern<Endian: BitOrder + Clone + std::fmt::Debug + PartialEq>(
    path: Option<&PathBuf>,
    pattern_file_path: &str,
    quiet_level: u64,
) -> BitPattern<Endian> {
    let bit_pattern = load_pattern_raw(path, pattern_file_path, quiet_level);
    wrap_pattern(bit_pattern)
}

/// Wrap a pattern in the typical pattern prolog and epilogue
///
/// - Prologue:
///     - A dot_star (to allow matches not starting at the beginning of data)
///     - A save_start (to record where the real match starts)
///
/// - Epilogue:
///     - A save_slot of 1 (to record where the pattern ended)
///     - A match with match_number 0 (to signal that we've got a match)
pub fn wrap_pattern<Endian: BitOrder + Clone + std::fmt::Debug + PartialEq>(
    inner_pattern: BitPattern<Endian>,
) -> BitPattern<Endian> {
    let mut program = BitPattern::get_dot_star();
    program.append(&BitPattern::get_save_start());
    program.append(&inner_pattern);
    program.append(&BitPattern::get_save(1));
    program.steps.push(Op::Match { match_number: 0 });
    program
}

pub fn run_pattern<Endian: BitOrder + Clone + PartialEq>(
    short_circuit: bool,
    data_file_path: &str,
    program: &BitPattern<Endian>,
    quiet_level: u64,
    use_memory_map: bool,
) -> Vec<Results> {
    let memmappeddata;
    let readdata;
    let data_vec: &[u8] = if use_memory_map {
        let file = File::open(data_file_path).unwrap();
        memmappeddata = unsafe { MmapOptions::new().map(&file).unwrap() };
        &memmappeddata[..]
    } else {
        readdata = fs::read(data_file_path).unwrap();
        readdata.as_slice()
    };
    run_pattern_data(short_circuit, data_vec, program, quiet_level)
}

pub fn run_pattern_data<Endian: BitOrder + Clone + PartialEq>(
    short_circuit: bool,
    data_vec: &[u8],
    program: &BitPattern<Endian>,
    quiet_level: u64,
) -> Vec<Results> {
    run_pattern_data_automata(
        short_circuit,
        data_vec,
        program,
        quiet_level,
        run_program::<Endian, states::StatesRingRcRing<ThreadRc>>,
    )
}

pub fn run_pattern_data_automata<Endian: BitOrder + Clone + PartialEq>(
    short_circuit: bool,
    data_vec: &[u8],
    program: &BitPattern<Endian>,
    quiet_level: u64,
    automata: fn(usize, &BitPattern<Endian>, &AddressedBits) -> Results,
) -> Vec<Results> {
    let mut start_idx = 0;

    let index_of_first_step_past_initial_dot_star_and_save = 4;

    if short_circuit {
        // Let's peek into the first "real" step of our pattern and see if we can
        // "cheat" to find where it matches so we don't really have to do much of
        // our dot_star that we added above (it's slow)
        if let Some(first_step) = program
            .steps
            .get(index_of_first_step_past_initial_dot_star_and_save)
        {
            match first_step {
                Op::Byte { value } => {
                    for (idx, byte_in) in data_vec.iter().enumerate() {
                        if byte_in == value {
                            let peeking_result;
                            let mut extra_peek = 1;
                            loop {
                                // Is our next operation also a "byte"?
                                if let Some(Op::Byte { value: value_next }) = program.steps.get(
                                    index_of_first_step_past_initial_dot_star_and_save + extra_peek,
                                ) {
                                    // Can we read the next byte of our data?
                                    if let Some(next_peek) = data_vec.get(idx + extra_peek) {
                                        if value_next == next_peek {
                                            // Looks like the next byte matches
                                            // as well... keep peeking
                                            extra_peek += 1;
                                            continue;
                                        } else {
                                            // We expected a byte, but it wasn't found
                                            peeking_result = false;
                                            break;
                                        }
                                    } else {
                                        // We couldn't read the next byte...
                                        // that doesn't bode well, but we'll
                                        // just stop peeking and continue with
                                        // the main logic from this point
                                        peeking_result = true;
                                        break;
                                    }
                                } else {
                                    // Next operation is not a byte... consider
                                    // this peek a success and stop peeking completely
                                    peeking_result = true;
                                    break;
                                }
                            }
                            if peeking_result {
                                start_idx = idx;
                                break;
                            }
                        }
                    }
                    if start_idx == 0 {
                        // We didn't find a single instance of our first byte... just
                        // set the start to the end and fall through (so we'll fail
                        // normally below)
                        start_idx = data_vec.len() - 1;
                    }
                }
                Op::Lookup { data } => {
                    let mut preview_idx = 0;
                    let mut cache = LookupCache::new(500);
                    loop {
                        for v in data {
                            let result = v.do_lookup_cached(
                                &mut cache,
                                &AddressedBits::new(
                                    &data_vec[preview_idx..],
                                    preview_idx.try_into().unwrap(),
                                ),
                                &program.tables,
                            );
                            if result.is_ok() {
                                // We had success... save this idx as where we
                                // should start for "real"
                                start_idx = preview_idx;
                            }
                        }
                        preview_idx += 1;
                        // If we're about to off the end of our data...
                        if preview_idx >= data_vec.len() {
                            // just set the start_idx to the end of our data and
                            // we'll fail out normally (and quickly) below
                            start_idx = data_vec.len() - 1;
                        }
                        // Stop previewing if we found a start_idx
                        if start_idx != 0 {
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Here's where we do the "real work"!
    let mut results = vec![];
    loop {
        // eprintln!("Start idx is: {:?}", start_idx);
        let mut result = automata(
            500,
            program,
            &AddressedBits::new(&data_vec[start_idx..], start_idx.try_into().unwrap()),
        );

        if result.matched {
            let mut keep_going = false;
            if let Some(x) = result.saved.as_mut() {
                let match_location = x.start.unwrap();

                // Update our start address to reflect the start_idx we started
                // searching at
                if let Some(x) = &mut x.start {
                    *x += start_idx;
                }

                // Update the offset of our captures to reflect the start_idx we
                // started searching at
                x.captures
                    .iter_mut()
                    .for_each(|(_key, val)| *val += start_idx);

                // Start looking for the next match just beyond this match
                start_idx += match_location + 1;
                keep_going = start_idx < data_vec.len();
            }
            if quiet_level == 0 {
                // If we're not trying to be quiet... print the whole result
                println!("{:#?}", result);
            }
            results.push(result);
            if !keep_going {
                break;
            }
        } else {
            break;
        }
    }

    // Save off some result information for pretty printing in the table
    // (data_file_path, num_matches, matches)
    results
}

/// Given a program, run it on the given data starting at index start_idx and
/// return a result which is an offset into data starting at start_idx
///
/// NOTICE! The return result is NOT an absolute offset into data_vec! Add
/// start_idx to the result to obtain the absolute offset.
pub fn run_pattern_data_once<Endian: BitOrder + Clone + PartialEq>(
    data_vec: &[u8],
    program: &BitPattern<Endian>,
    _quiet_level: u64,
    start_idx: usize,
) -> Results {
    // Run one iteration of the run_pattern_data algorithm
    run_program::<Endian, states::StatesRingRcRing<ThreadRc>>(
        500,
        program,
        &data_vec[start_idx..].into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, ffi::CString};
    use treesearchlib::automata::states::*;
    use treesearchlib::automata::thread::SavedData;

    #[test]
    fn test_workflow() {
        let c_ptn = CString::new(
            r#"{
            "tables": [],
            "steps": [
                {
                    "type": "BYTE",
                    "value": 65
                }, {
                    "type": "BYTE",
                    "value": 66
                }
            ]
        }"#,
        )
        .unwrap()
        .into_bytes();

        let prog = load_pattern_from_data::<Msb0>(&c_ptn, 3);
        let expected1 = BitPattern::<Msb0> {
            steps: vec![Op::Byte { value: 65 }, Op::Byte { value: 66 }],
            tables: vec![],
        };
        assert_eq!(prog, expected1);

        let wrapped_prog = wrap_pattern(prog);
        let expected2 = BitPattern::<Msb0> {
            steps: vec![
                Op::Split { dest1: 3, dest2: 1 },
                Op::AnyByte,
                Op::Jmp { dest: 0 },
                Op::SaveStart,
                Op::Byte { value: 65 },
                Op::Byte { value: 66 },
                Op::Save { slot: 1 },
                Op::Match { match_number: 0 },
            ],
            tables: vec![],
        };
        assert_eq!(wrapped_prog, expected2);

        let c_data = CString::new("ZZzzZZzzABZZzzZZzzABQQ").unwrap().into_bytes();
        let results = run_pattern_data(false, &c_data, &wrapped_prog, 3);
        let mut captures1 = BTreeMap::new();
        captures1.insert(1, 10);
        let mut captures2 = BTreeMap::new();
        captures2.insert(1, 20);
        let expected3 = vec![
            Results {
                matched: true,
                match_number: Some(0),
                saved: Some(SavedData {
                    start: Some(8),
                    captures: captures1,
                    variables: BTreeMap::new(),
                    labels: BTreeMap::new(),
                    values: BTreeMap::new(),
                }),
            },
            Results {
                matched: true,
                match_number: Some(0),
                saved: Some(SavedData {
                    start: Some(18),
                    captures: captures2,
                    variables: BTreeMap::new(),
                    labels: BTreeMap::new(),
                    values: BTreeMap::new(),
                }),
            },
        ];
        assert_eq!(results, expected3);

        let results = run_pattern_data_once(&c_data, &wrapped_prog, 3, 6);
        let mut captures1 = BTreeMap::new();
        captures1.insert(1, 4);
        let expected4 = Results {
            matched: true,
            match_number: Some(0),
            saved: Some(SavedData {
                start: Some(2),
                captures: captures1,
                variables: BTreeMap::new(),
                labels: BTreeMap::new(),
                values: BTreeMap::new(),
            }),
        };
        assert_eq!(results, expected4);
    }

    /// The following is:
    /// ```text
    ///        0001f0b0 be 88           ldrh       r6,[r7,#0x4]
    ///        0001f0b2 01 91           str        r1,[sp,#local_16c]
    ///        0001f0b4 28 49           ldr        r1,[DAT_0001f158]                                = 0001666Ah
    ///        0001f0b6 00 96           str        r6,[sp,#0x0]=>local_170
    ///        0001f0b8 02 94           str        r4,[sp,#local_168]
    ///        0001f0ba 79 44           add        r1=>s_Telling_server_to_connect_to_%d._0003572   = "Telling server to connect to
    ///        0001f0bc f7 f7 28 ed     blx        Curl_infof                                       undefined Curl_infof()
    ///        0001f0c0 dd f8 1c e0     ldr.w      lr,[sp,#local_154]
    ///        0001f0c4 28 46           mov        r0,r5
    ///        0001f0c6 3a 88           ldrh       r2,[r7,#0x0]
    ///        0001f0c8 27 0a           lsrs       r7,r4,#0x8
    ///        0001f0ca e4 b2           uxtb       r4,r4
    ///        0001f0cc be f8 06 10     ldrh.w     r1,[lr,#0x6]
    ///        0001f0d0 be f8 02 30     ldrh.w     r3,[lr,#0x2]
    ///        0001f0d4 be f8 04 60     ldrh.w     r6,[lr,#0x4]
    ///        0001f0d8 01 91           str        r1,[sp,#local_16c]
    ///        0001f0da 20 49           ldr        r1,[DAT_0001f15c]                                = 00016672h
    ///        0001f0dc 02 97           str        r7,[sp,#local_168]
    ///        0001f0de 03 94           str        r4,[sp,#local_164]
    /// ```
    const INPUT: [u8; 48] = [
        0xbe, 0x88, 0x01, 0x91, 0x28, 0x49, 0x00, 0x96, 0x02, 0x94, 0x79, 0x44, 0xf7, 0xf7, 0x28,
        0xed, 0xdd, 0xf8, 0x1c, 0xe0, 0x28, 0x46, 0x3a, 0x88, 0x27, 0x0a, 0xe4, 0xb2, 0xbe, 0xf8,
        0x06, 0x10, 0xbe, 0xf8, 0x02, 0x30, 0xbe, 0xf8, 0x04, 0x60, 0x01, 0x91, 0x20, 0x49, 0x02,
        0x97, 0x03, 0x94,
    ];

    /// The following is this pattern compiled:
    /// ```text
    /// ;`=0x04`
    /// ;`=0x60`
    /// `=0x01`
    /// `=0x91`
    /// ldr r1,[`:Q1`]
    /// ```
    const C_PTN: &str = r##"{"tables":[],"steps":[{
                "type": "BYTE",
                "value": 1
            },
            {
                "type": "BYTE",
                "value": 145
            },
            {
                "data": [{
                    "type": "MaskAndChoose",
                    "choices": [{
                        "operands": [{
                            "expression": {
                                "op": "Add",
                                "children": {
                                    "left": {
                                        "op": "And",
                                        "children": {
                                            "left": {
                                                "op": "Add",
                                                "children": {
                                                    "left": {"op": "StartInstructionValue"},
                                                    "right": {
                                                        "op": "ConstantValue",
                                                        "value": 4
                                                    }
                                                }
                                            },
                                            "right": {
                                                "op": "ConstantValue",
                                                "value": 4294967292
                                            }
                                        }
                                    },
                                    "right": {
                                        "op": "Mult",
                                        "children": {
                                            "left": {
                                                "op": "ConstantValue",
                                                "value": 4
                                            },
                                            "right": {
                                                "op": "OperandValue",
                                                "offset": 0,
                                                "child": {
                                                    "op": "TokenField",
                                                    "value": {
                                                        "bitend": 7,
                                                        "shift": 0,
                                                        "signbit": false,
                                                        "bitstart": 0,
                                                        "byteend": 0,
                                                        "bigendian": false,
                                                        "bytestart": 0
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "var_id": ":Q1",
                            "type": "Scalar",
                            "mask": [
                                255,
                                0
                            ]
                        }],
                        "value": [
                            0,
                            73
                        ]
                    }],
                    "mask": [
                        0,
                        255
                    ]
                }],
                "type": "LOOKUP"
            }],"compile_info":[{"compiled_using_binary":[{"path":["unknown"],"compiled_at_address":["01008420"],"md5":["unknown"]}],"language_id":["ARM:LE:32:v8"]}],"pattern_metadata":{}}"##;

    #[test]
    /// This test ensures that we properly compute label addresses when we have
    /// a single match. This should be the same match (more or less) as the
    /// second match in [test_labels_in_misaligned_multiple_matches] and have
    /// the correct label value.
    ///
    /// This test confirms we are properly computing the label value in the
    /// less-complicated case of a single match, so we can prove if we're
    /// messing things up in the more complicated case of two or more matches
    /// (as tested by [test_labels_in_misaligned_multiple_matches]).
    fn test_labels_single_match() {
        let mut prog =
            load_pattern_from_data::<Msb0>(&CString::new(C_PTN).unwrap().into_bytes(), 3);

        // These extra two bytes ensure that we're only going to hit the second
        // address-based-ldr in our data
        let prepended_bytes = load_pattern_from_data(
            CString::new(
                r##"{"tables":[],"steps":[{
                    "type": "BYTE",
                    "value": 4
                },
                {
                    "type": "BYTE",
                    "value": 96
                }
            ]}"##,
            )
            .unwrap()
            .to_bytes(),
            3,
        );
        prog.prepend(&prepended_bytes);

        let prog = wrap_pattern(prog);

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
            let results = run_pattern_data_automata(false, &INPUT, &prog, 0, method);
            // eprintln!("Results: {:?}", results);
            assert_eq!(
                1,
                results.len(),
                "Expected result but got {} for method count {}",
                results.len(),
                count
            );

            // Check the first result
            let result = results.first().unwrap();
            assert_eq!(result.match_number.unwrap(), 0, "Count is: {}", count);
            let saved = result.saved.as_ref().expect("msg");
            // Ensure only one label is populated
            assert_eq!(saved.labels.len(), 1, "Count is: {}", count);
            // Ensure that label is "Q1" and has the right value
            assert_eq!(
                saved.labels.get("Q1").unwrap().to_owned(),
                0xac,
                "Count is: {}",
                count
            );
        }
    }

    #[test]
    /// This test ensures that we properly compute label addresses when we have
    /// multiple matches (so we're not starting from the start of the binary for
    /// each match)
    fn test_labels_in_misaligned_multiple_matches() {
        let prog = load_pattern_from_data::<Msb0>(&CString::new(C_PTN).unwrap().into_bytes(), 3);

        let prog = wrap_pattern(prog);

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
            let results = run_pattern_data_automata(false, &INPUT, &prog, 0, method);
            // eprintln!("Results: {:?}", results);
            assert_eq!(
                2,
                results.len(),
                "Expected two results but got {} for method count {}",
                results.len(),
                count
            );

            // Check the first result
            let result = results.first().unwrap();
            assert_eq!(result.match_number.unwrap(), 0, "Count is: {}", count);
            let saved = result.saved.as_ref().expect("msg");
            // Ensure only one label is populated
            assert_eq!(saved.labels.len(), 1, "Count is: {}", count);
            // Ensure that label is "Q1" and has the right value
            assert_eq!(
                saved.labels.get("Q1").unwrap().to_owned(),
                0xa8,
                "Count is: {}",
                count
            );

            // Check the second result
            let result = results.get(1).unwrap();
            assert_eq!(result.match_number.unwrap(), 0, "Count is: {}", count);
            let saved = result.saved.as_ref().expect("msg");
            // Ensure only one label is populated
            assert_eq!(saved.labels.len(), 1, "Count is: {}", count);
            // Ensure that label is "Q1" and has the right value
            assert_eq!(
                saved.labels.get("Q1").unwrap().to_owned(),
                0xac,
                "Count is: {}",
                count
            );
        }
    }

    /// The following is this pattern compiled:
    /// ```text
    /// `Foo:`
    /// `=0x01`
    /// ```
    const C_LABELS_PTN: &str = r##"{"tables":[],"steps":[
    {
        "type": "LABEL",
        "value": "Foo"
    },
    {
        "type": "BYTE",
        "value": 1
    }],"compile_info":[{"compiled_using_binary":[{"path":["unknown"],"compiled_at_address":["01008420"],"md5":["unknown"]}],"language_id":["ARM:LE:32:v8"]}],"pattern_metadata":{}}"##;

    const LABELS_INPUT: [u8; 8] = [0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x1];

    #[test]
    /// This tests that multiple matches produce the proper label values.
    ///
    /// This catches a regression mistakenly added with multiple-hit label
    /// calculation.
    fn test_simple_labels() {
        let prog =
            load_pattern_from_data::<Msb0>(&CString::new(C_LABELS_PTN).unwrap().into_bytes(), 3);

        let prog = wrap_pattern(prog);

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
            let results = run_pattern_data_automata(false, &LABELS_INPUT, &prog, 0, method);
            // eprintln!("Results: {:?}", results);
            assert_eq!(
                2,
                results.len(),
                "Expected result but got {} for method count {}",
                results.len(),
                count
            );

            // Check the first result
            let result = results.first().unwrap();
            assert_eq!(result.match_number.unwrap(), 0, "Count is: {}", count);
            let saved = result.saved.as_ref().expect("msg");
            // Ensure only one label is populated
            assert_eq!(saved.labels.len(), 1, "Count is: {}", count);
            // Ensure that label is "Q1" and has the right value
            assert_eq!(
                saved.labels.get("Foo").unwrap().to_owned(),
                0x4,
                "Count is: {}",
                count
            );

            // Check the second result
            let result = results.get(1).unwrap();
            assert_eq!(result.match_number.unwrap(), 0, "Count is: {}", count);
            let saved = result.saved.as_ref().expect("msg");
            // Ensure only one label is populated
            assert_eq!(saved.labels.len(), 1, "Count is: {}", count);
            // Ensure that label is "Foo" and has the right value
            assert_eq!(
                saved.labels.get("Foo").unwrap().to_owned(),
                0x7,
                "Count is: {}",
                count
            );
        }
    }
}
