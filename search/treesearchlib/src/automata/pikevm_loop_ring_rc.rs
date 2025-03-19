//! This improvement builds off of
//! [pikevm_loop_ring](crate::automata::pikevm_loop_ring) but keeps track of
//! saved state in threads using [reference counted](Rc) data structures which
//! avoid copying states unless they're actually modified (instead multiple
//! threads can point at the same state and a new state will only copied when a
//! write is about to be performed)
//!
//! The next improvement is in
//! [pikevm_loop_ring_rc_fixed](crate::automata::pikevm_loop_ring_rc_fixed)

// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use alloc::rc::Rc;
use core::clone::Clone;
use core::convert::TryInto;
extern crate test;

use bitvec::prelude::*;

use crate::automata::results::*;
use crate::automata::thread::{SavedData, ThreadRc};
use crate::bitstructs::{AddressedBits, LookupCache, Op, Pattern};

use super::states::StatesRc;

// The following two lines can be uncommented (along with the corrisponding
// function annotations) to enable mutation testing using the mutagen crate
// (which also must be uncommented in Cargo.toml). These lines are not left in
// because they cause lots of red with Cargo-analyzer's VSCode configuration
// (although they seem to work fine otherwise)

// #[cfg(test)] use
// mutagen::mutate;

pub fn run_program<Endian: BitOrder + Clone + PartialEq, S: StatesRc<ThreadRc>>(
    max_cache_size: usize,
    prog: &Pattern<Endian>,
    input: &AddressedBits,
) -> Results {
    let mut states = S::new();
    pikevm_inner_new_rc(max_cache_size, prog, input, &mut states)
}

// #[cfg_attr(test, mutate)]
pub fn process_thread_rc<Endian: BitOrder + Clone + PartialEq, S: StatesRc<ThreadRc>>(
    thread: &mut ThreadRc,
    sp: usize,
    prog: &Pattern<Endian>,
    input: &AddressedBits,
    states: &mut S,
    cache: &mut LookupCache<Endian>,
) -> Option<Results> {
    let mut pc = thread.pc_idx;
    let saved = &mut thread.saved;
    let mut start = thread.start;
    loop {
        match prog.steps.get(pc).unwrap() {
            Op::Byte { value } => {
                if input.len() > sp && *value == input[sp] {
                    states.add(sp + 1, ThreadRc::new(pc + 1, saved, start));
                }
                break;
            }
            Op::MaskedByte { mask, value } => {
                if input.len() > sp && *value == (input[sp] & *mask) {
                    states.add(sp + 1, ThreadRc::new(pc + 1, saved, start));
                }
                break;
            }
            Op::ByteMultiNonconsuming { value } => {
                if input.len() > sp && value.contains(&input[sp]) {
                    states.add(sp, ThreadRc::new(pc + 1, saved, start));
                }
                break;
            }
            Op::Match { match_number } => {
                let mut final_saved = Rc::make_mut(saved).clone();
                final_saved.start = start;
                return Some(Results {
                    matched: true,
                    match_number: Some(*match_number),
                    saved: Some(final_saved),
                });
            }
            Op::Jmp { dest } => {
                pc = *dest;
                // states.add(sp, Thread::new(*dest, &saved, start));
            }
            Op::Split { dest1, dest2 } => {
                states.add(sp, ThreadRc::new(*dest1, saved, start));
                // states.add(sp, Thread::new(*dest2, &saved, start));
                pc = *dest2;
            }
            Op::SplitMulti { dests } => {
                if !dests.is_empty() {
                    pc = *dests.first().unwrap();
                    if dests.len() > 1 {
                        for dest in &dests[1..] {
                            states.add(sp, ThreadRc::new(*dest, saved, start));
                        }
                    }
                } else {
                    break;
                }
            }
            Op::SaveStart => {
                start = Some(sp);
                pc += 1;
            }
            Op::Save { slot } => {
                // let saved_ready_to_mut = Rc::make_mut(saved);

                // saved_ready_to_mut.captures.insert(*slot, sp);
                // // states.add(sp, Thread::new(pc + 1, &saved, start));
                // *saved = Rc::new(saved_ready_to_mut.clone());
                Rc::make_mut(saved).captures.insert(*slot, sp);
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
                    Rc::make_mut(saved)
                        .labels
                        .insert(value.clone(), this_label_value);
                }
                pc += 1;
            }
            Op::AnyByte => {
                states.add(sp + 1, ThreadRc::new(pc + 1, saved, start));
                break;
            }
            Op::AnyByteSequence { min, max, interval } => {
                for i in (*min..(*max + 1)).step_by(*interval) {
                    states.add(sp + i, ThreadRc::new(pc + 1, saved, start));
                }
                break;
            }
            Op::Lookup { data } => {
                for v in data {
                    let result = v.do_lookup_with_saved_state_rc(
                        cache,
                        &input.get_range(sp..),
                        &prog.tables,
                        saved,
                    );
                    if let Ok(good_result) = result {
                        states.add(sp + good_result.size, ThreadRc::new(pc + 1, saved, start));
                        break;
                    }
                }
                break;
            }
            Op::LookupQuick { bytes, data } => {
                if input.len() > sp && !bytes.contains(&input[sp]) {
                    break;
                }
                for v in data {
                    let result = v.do_lookup_with_saved_state_rc(
                        cache,
                        &input.get_range(sp..),
                        &prog.tables,
                        saved,
                    );
                    if let Ok(good_result) = result {
                        states.add(sp + good_result.size, ThreadRc::new(pc + 1, saved, start));
                        break;
                    }
                }
                break;
            }
            Op::NegativeLookahead { pattern } => {
                // If our sub-pattern doesn't match, continue to the next
                // step. If it did match, then we'll stop processing this
                // thread without adding a next state
                if !run_program::<Endian, S>(10, pattern, &input.get_range(sp..)).matched {
                    pc += 1;
                } else {
                    break;
                }
            }
        }
    }
    None
}

// #[cfg_attr(test, mutate)]
pub fn pikevm_inner_new_rc<Endian: BitOrder + Clone + PartialEq, S: StatesRc<ThreadRc>>(
    max_cache_size: usize,
    prog: &Pattern<Endian>,
    input: &AddressedBits,
    states: &mut S,
) -> Results {
    let mut cache = LookupCache::new(max_cache_size);

    states.add(0, ThreadRc::new(0, &Rc::new(SavedData::default()), None));
    let mut sp = 0;
    while sp <= input.len() {
        // eprintln!("{}->{}", input.len(), sp);

        loop {
            let option_next_thread = states.get_next_thread(sp);
            if option_next_thread.is_none() {
                break;
            }
            let mut t = option_next_thread.unwrap();

            if let Some(x) = process_thread_rc(&mut t, sp, prog, input, states, &mut cache) {
                return x;
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
