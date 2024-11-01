//! This improvement builds off of
//! [pikevm_loop_ring_rc_fixed](crate::automata::pikevm_loop_ring_rc_fixed).
//!
//! This was an experiment with not using a cache... turns out for random input
//! data a cache performs more or less the same as no cache
//!
//! This is currently the most-optimized automata

// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

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

pub fn run_program<Endian: BitOrder + Clone + PartialEq, State: StatesRc<ThreadRc>>(
    max_cache_size: usize,
    prog: &Pattern<Endian>,
    input: &AddressedBits,
) -> Results {
    // let mut states = StatesRingRcFixed::new(&mut bytes);
    let mut states = State::new();

    pikevm_inner_new_rc::<Endian, State>(max_cache_size, prog, input, &mut states)
}

fn add_thread<Endian: BitOrder + Clone + PartialEq, State: StatesRc<ThreadRc>>(
    prog: &Pattern<Endian>,
    states: &mut State, //StatesRingRcFixed<ThreadRc>,
    sp: usize,
    pc: usize,
    input: &AddressedBits,
    saved: &mut Rc<SavedData>,
    start: Option<usize>,
) {
    match prog.steps.get(pc).unwrap() {
        Op::ByteMultiNonconsuming { value } => {
            if input.len() > sp && value.contains(&input[sp]) {
                add_thread::<Endian, State>(prog, states, sp, pc + 1, input, saved, start);
            }
        }
        Op::Jmp { dest } => {
            add_thread::<Endian, State>(prog, states, sp, *dest, input, saved, start);
        }
        Op::Split { dest1, dest2 } => {
            add_thread::<Endian, State>(
                prog,
                states,
                sp,
                *dest1,
                input,
                &mut Rc::clone(saved),
                start,
            );
            add_thread::<Endian, State>(
                prog,
                states,
                sp,
                *dest2,
                input,
                &mut Rc::clone(saved),
                start,
            );
        }
        Op::SplitMulti { dests } => {
            if !dests.is_empty() {
                for dest in &dests[..] {
                    add_thread::<Endian, State>(
                        prog,
                        states,
                        sp,
                        *dest,
                        input,
                        &mut Rc::clone(saved),
                        start,
                    );
                }
            } else {
                panic!("Cannot have an empty SplitMulti!");
            }
        }
        Op::SaveStart => {
            add_thread::<Endian, State>(prog, states, sp, pc + 1, input, saved, Some(sp));
        }
        Op::Save { slot } => {
            // let saved_ready_to_mut = Rc::make_mut(saved);

            // saved_ready_to_mut.captures.insert(*slot, sp);
            // // states.add(sp, Thread::new(pc + 1, &saved));
            // *saved = Rc::new(saved_ready_to_mut.clone());
            Rc::make_mut(saved).captures.insert(*slot, sp);
            add_thread::<Endian, State>(prog, states, sp, pc + 1, input, saved, start);
        }
        Op::Label { value } => {
            Rc::make_mut(saved).labels.insert(
                value.clone(),
                TryInto::<i128>::try_into(sp).unwrap() + i128::from(input.get_base_address()),
            );
            add_thread::<Endian, State>(prog, states, sp, pc + 1, input, saved, start);
        }
        _ => states.add(sp, ThreadRc::new(pc, saved, start)),
    }
}

// #[cfg_attr(test, mutate)]
pub fn process_thread_rc<Endian: BitOrder + Clone + PartialEq, State: StatesRc<ThreadRc>>(
    thread: &mut ThreadRc,
    sp: usize,
    prog: &Pattern<Endian>,
    input: &AddressedBits,
    states: &mut State, // StatesRingRcFixed<ThreadRc>,
    cache: &mut LookupCache<Endian>,
) -> Option<Results> {
    let mut pc = thread.pc_idx;
    let saved = &mut thread.saved;
    let start = thread.start;
    loop {
        match prog.steps.get(pc).unwrap() {
            Op::Byte { value } => {
                if input.len() > sp && *value == input[sp] {
                    add_thread::<Endian, State>(prog, states, sp + 1, pc + 1, input, saved, start);
                }
                break;
            }
            Op::MaskedByte { mask, value } => {
                if input.len() > sp && *value == (input[sp] & *mask) {
                    add_thread::<Endian, State>(prog, states, sp + 1, pc + 1, input, saved, start);
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
            Op::AnyByte => {
                add_thread::<Endian, State>(prog, states, sp + 1, pc + 1, input, saved, start);
                break;
            }
            Op::AnyByteSequence { min, max, interval } => {
                for i in (*min..(*max + 1)).step_by(*interval) {
                    add_thread::<Endian, State>(prog, states, sp + i, pc + 1, input, saved, start);
                }
                break;
            }
            Op::Lookup { data } => {
                for v in data {
                    let result = v.do_lookup_with_saved_state_rc_no_cache(
                        cache,
                        &input.get_range(sp..),
                        &prog.tables,
                        saved,
                    );
                    if let Ok(good_result) = result {
                        add_thread::<Endian, State>(
                            prog,
                            states,
                            sp + good_result.size,
                            pc + 1,
                            input,
                            saved,
                            start,
                        );
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
                    let result = v.do_lookup_with_saved_state_rc_no_cache(
                        cache,
                        &input.get_range(sp..),
                        &prog.tables,
                        saved,
                    );
                    if let Ok(good_result) = result {
                        add_thread::<Endian, State>(
                            prog,
                            states,
                            sp + good_result.size,
                            pc + 1,
                            input,
                            saved,
                            start,
                        );
                        break;
                    }
                }
                break;
            }
            Op::NegativeLookahead { pattern } => {
                // If our sub-pattern doesn't match, continue to the next
                // step. If it did match, then we'll stop processing this
                // thread without adding a next state
                if !run_program::<Endian, State>(10, pattern, &input.get_range(sp..)).matched {
                    pc += 1;
                } else {
                    break;
                }
            }
            _ => {
                panic!("Shouldn't have gotten this op here!")
            }
        }
    }
    None
}

// #[cfg_attr(test, mutate)]
pub fn pikevm_inner_new_rc<Endian: BitOrder + Clone + PartialEq, State: StatesRc<ThreadRc>>(
    max_cache_size: usize,
    prog: &Pattern<Endian>,
    input: &AddressedBits,
    states: &mut State, // StatesRingRcFixed<ThreadRc>,
) -> Results {
    let mut cache = LookupCache::new(max_cache_size);

    add_thread::<Endian, State>(
        prog,
        states,
        0,
        0,
        input,
        &mut Rc::new(SavedData::default()),
        None,
    );

    // add_thread::<Endian, State>(prog, states, 0, 0, &mut Rc::new(SavedData::default()));
    // eprintln!("Inital states: {:#?}", states);
    let mut sp = 0;
    while sp <= input.len() {
        // eprintln!("{}->{}", input.len(), sp);
        // eprintln!("States: {:?}", states);

        loop {
            let option_next_thread = states.get_next_thread(sp);
            if option_next_thread.is_none() {
                break;
            }
            let mut t = option_next_thread.unwrap();
            // eprintln!("Pulled thread: pc={} at sp {}", t.pc_idx, sp);

            if let Some(x) =
                process_thread_rc::<Endian, State>(&mut t, sp, prog, input, states, &mut cache)
            {
                return x;
            }
            // eprintln!("After States: {:?}", states);
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
