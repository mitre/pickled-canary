//! This works the same as [crate::automata::pikevm] but adds a loop where we
//! process as many steps with episalon transitions as possible in a given
//! thread before creating (and saving) a new thread. In other words, after
//! processing a "save" step we will proceed to process the next step right away
//! rather than saving the next step to process later. Similarly, we'll process
//! the first path of a "split" step directly (only saving the second path for
//! later processing) rather than saving both. This greatly reduces how many
//! threads need to be saved.
//!
//! This improvement was inspired by the Regex crate.
//!
//! The next improvement is combining the [crate::automata::pikevm_ring]
//! improvement with this improvement. This can be found in
//! [crate::automata::pikevm_loop_ring]

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
    pikevm_inner_loop(max_cache_size, prog, input, &mut states)
}

pub fn process_thread<Endian: BitOrder + Clone + PartialEq, T: States>(
    mut pc: usize,
    saved: &mut SavedData,
    sp: usize,
    prog: &Pattern<Endian>,
    input: &AddressedBits,
    states: &mut T,
    cache: &mut LookupCache<Endian>,
) -> Option<Results> {
    // eprintln!("Starting to process new thread");
    loop {
        // eprintln!("Processing step: {}", pc);
        match prog.steps.get(pc).unwrap() {
            Op::Byte { value } => {
                if input.len() > sp && *value == input[sp] {
                    states.add(sp + 1, Thread::new(pc + 1, saved));
                }
                break;
            }
            Op::MaskedByte { mask, value } => {
                if input.len() > sp && *value == (input[sp] & *mask) {
                    states.add(sp + 1, Thread::new(pc + 1, saved));
                }
                break;
            }
            Op::ByteMultiNonconsuming { value } => {
                if input.len() > sp && value.contains(&input[sp]) {
                    states.add(sp, Thread::new(pc + 1, saved));
                }
                break;
            }
            Op::Match { match_number } => {
                return Some(Results {
                    matched: true,
                    match_number: Some(*match_number),
                    saved: Some((*saved).clone()),
                });
            }
            Op::Jmp { dest } => {
                pc = *dest;
                // states.add(sp, Thread::new(*dest, &saved));
            }
            Op::Split { dest1, dest2 } => {
                states.add(sp, Thread::new(*dest1, saved));
                // states.add(sp, Thread::new(*dest2, &saved));
                pc = *dest2;
            }
            Op::SplitMulti { dests } => {
                if !dests.is_empty() {
                    pc = *dests.first().unwrap();
                    if dests.len() > 1 {
                        for dest in &dests[1..] {
                            states.add(sp, Thread::new(*dest, saved));
                        }
                    }
                } else {
                    break;
                }
            }
            Op::SaveStart => {
                saved.start = Some(sp);
                pc += 1;
            }
            Op::Save { slot } => {
                saved.captures.insert(*slot, sp);
                // states.add(sp, Thread::new(pc + 1, &saved));
                pc += 1;
            }
            Op::Label { value } => {
                let this_label_value =
                    TryInto::<i128>::try_into(sp).unwrap() + i128::from(input.get_base_address());

                if let Some(existing_value) = saved.labels.get(&value.clone()) {
                    if *existing_value != this_label_value {
                        break;
                    }
                } else {
                    saved.labels.insert(value.clone(), this_label_value);
                }
                pc += 1;
            }
            Op::AnyByte => {
                states.add(sp + 1, Thread::new(pc + 1, saved));
                break;
            }
            Op::AnyByteSequence { min, max, interval } => {
                for i in (*min..(*max + 1)).step_by(*interval) {
                    states.add(sp + i, Thread::new(pc + 1, saved));
                }
                break;
            }
            Op::Lookup { data } | Op::LookupQuick { bytes: _, data } => {
                for v in data {
                    let result = v.do_lookup_with_saved_state(
                        cache,
                        &input.get_range(sp..),
                        &prog.tables,
                        saved,
                    );
                    if let Ok(good_result) = result {
                        states.add(sp + good_result.size, Thread::new(pc + 1, saved));
                        break;
                    }
                }
                break;
            }
            Op::NegativeLookahead { pattern } => {
                // If our sub-pattern doesn't match, continue to the next
                // step. If it did match, then we'll stop processing this
                // thread without adding a next state
                if !run_program(10, pattern, &input.get_range(sp..)).matched {
                    pc += 1;
                } else {
                    break;
                }
            }
        }
    }
    None
}

pub fn pikevm_inner_loop<Endian: BitOrder + Clone + PartialEq, T: States>(
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
        // eprintln!("Moving to new byte");
        loop {
            let option_next_thread = states.get_next_thread(sp);
            if option_next_thread.is_none() {
                break;
            }
            let mut t = option_next_thread.unwrap();

            if let Some(x) =
                process_thread(t.pc_idx, &mut t.saved, sp, prog, input, states, &mut cache)
            {
                return x;
            }
        }
        states.clear_old_states(sp);
        sp += 1;
        // eprintln!("States: {:#?}", states);
    }

    Results {
        matched: false,
        match_number: None,
        saved: None,
    }
}
