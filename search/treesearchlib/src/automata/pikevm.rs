//! This is the third simplest-to-understand automata (after
//! [crate::automata::recursive_backtracking_loop]). This only visits each byte
//! being searched a single time, greatly improving performance.
//!
//! The general approach here mirrors the "Pike's Implementation" described
//! here: https://swtch.com/~rsc/regexp/regexp2.html
//!
//! The next improvement is found in [crate::automata::pikevm_ring]

// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use core::clone::Clone;
use core::convert::TryInto;
extern crate test;

use bitvec::prelude::*;

use crate::automata::results::*;
use crate::automata::states::{States, StatesHash};
use crate::automata::thread::{SavedData, Thread};
use crate::bitstructs::{AddressedBits, LookupCache, Op, Pattern};

pub fn run_program<Endian: BitOrder + Clone + PartialEq>(
    max_cache_size: usize,
    prog: &Pattern<Endian>,
    input: &AddressedBits,
) -> Results {
    let mut states = StatesHash::new();
    pikevm_inner(max_cache_size, prog, input, &mut states)
}

pub fn pikevm_inner<Endian: BitOrder + Clone + PartialEq, T: States>(
    max_cache_size: usize,
    prog: &Pattern<Endian>,
    input: &AddressedBits,
    states: &mut T,
) -> Results {
    let mut cache = LookupCache::new(max_cache_size);

    states.add(0, Thread::new(0, &SavedData::default()));
    let mut sp = 0;
    while sp <= input.len() {
        // eprintln!("{}->{}", input.len(), sp);
        loop {
            let option_next_thread = states.get_next_thread(sp);
            if option_next_thread.is_none() {
                break;
            }
            let mut t = option_next_thread.unwrap();

            let pc = t.pc_idx;
            match prog
                .steps
                .get(pc)
                .expect("Ran out of steps in the pattern. Did the program end with a match?")
            {
                Op::Byte { value } => {
                    if input.len() > sp && *value == input[sp] {
                        states.add(sp + 1, Thread::new(pc + 1, &t.saved));
                    }
                }
                Op::MaskedByte { mask, value } => {
                    if input.len() > sp && *value == (input[sp] & *mask) {
                        states.add(sp + 1, Thread::new(pc + 1, &t.saved));
                    }
                }
                Op::ByteMultiNonconsuming { value } => {
                    if input.len() > sp && value.contains(&input[sp]) {
                        states.add(sp, Thread::new(pc + 1, &t.saved));
                    }
                }
                Op::Match { match_number } => {
                    return Results {
                        matched: true,
                        match_number: Some(*match_number),
                        saved: Some(t.saved),
                    };
                }
                Op::Jmp { dest } => {
                    states.add(sp, Thread::new(*dest, &t.saved));
                }
                Op::Split { dest1, dest2 } => {
                    states.add(sp, Thread::new(*dest1, &t.saved));
                    states.add(sp, Thread::new(*dest2, &t.saved));
                }
                Op::SplitMulti { dests } => {
                    for dest in dests {
                        states.add(sp, Thread::new(*dest, &t.saved));
                    }
                }
                Op::SaveStart => {
                    t.saved.start = Some(sp);
                    states.add(sp, Thread::new(pc + 1, &t.saved));
                }
                Op::Save { slot } => {
                    t.saved.captures.insert(*slot, sp);
                    states.add(sp, Thread::new(pc + 1, &t.saved));
                }
                Op::Label { value } => {
                    let this_label_value = TryInto::<i128>::try_into(sp).unwrap()
                        + i128::from(input.get_base_address());

                    if let Some(existing_value) = t.saved.labels.get(&value.clone()) {
                        if *existing_value != this_label_value {
                            continue;
                        }
                    } else {
                        t.saved.labels.insert(value.clone(), this_label_value);
                    }
                    states.add(sp, Thread::new(pc + 1, &t.saved));
                }
                Op::AnyByte => states.add(sp + 1, Thread::new(pc + 1, &t.saved)),
                Op::AnyByteSequence { min, max, interval } => {
                    for i in (*min..(*max + 1)).step_by(*interval) {
                        states.add(sp + i, Thread::new(pc + 1, &t.saved));
                    }
                }

                Op::Lookup { data } | Op::LookupQuick { bytes: _, data } => {
                    for v in data {
                        let result = v.do_lookup_with_saved_state(
                            &mut cache,
                            &input.get_range(sp..),
                            &prog.tables,
                            &mut t.saved,
                        );
                        if let Ok(good_result) = result {
                            states.add(sp + good_result.size, Thread::new(pc + 1, &t.saved));
                            break;
                        }
                    }
                }
                Op::NegativeLookahead { pattern } => {
                    // If our sub-pattern doesn't match, continue to the next
                    // step. If it did match, then we'll stop processing this
                    // thread without adding a next state
                    if !run_program(max_cache_size, pattern, &input.get_range(sp..)).matched {
                        states.add(sp, Thread::new(pc + 1, &t.saved));
                    }
                }
            }
        }
        states.clear_old_states(sp);
        sp += 1;
    }

    Results {
        matched: false,
        match_number: None,
        saved: None,
    }
}
