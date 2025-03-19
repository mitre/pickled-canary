//! This is the simplest-to-understand automata implementation, but also one
//! that overflows the stack very easily.
//!
//! The general approach here mirrors the "A Recursive Backtracking
//! Implementation" described here: https://swtch.com/~rsc/regexp/regexp2.html
//!
//! For an improvement on this technique see
//! [crate::automata::recursive_backtracking_loop]

// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use core::clone::Clone;
use core::convert::TryInto;
extern crate test;

use bitvec::prelude::*;

use crate::automata::results::*;
use crate::automata::thread::SavedData;
use crate::bitstructs::{AddressedBits, LookupCache, Op, Pattern};

pub fn run_program<Endian: BitOrder + Clone + PartialEq>(
    max_cache_size: usize,
    prog: &Pattern<Endian>,
    input: &AddressedBits,
) -> Results {
    let mut saved = SavedData::new();
    let mut cache = LookupCache::new(max_cache_size);
    recursive_backtracking_helper(&mut cache, prog, input, 0, 0, &mut saved)
}

pub fn recursive_backtracking_helper<Endian: BitOrder + Clone + PartialEq>(
    cache: &mut LookupCache<Endian>,
    prog: &Pattern<Endian>,
    input: &AddressedBits,
    pc: usize,
    sp: usize,
    saved: &mut SavedData,
) -> Results {
    match prog.steps.get(pc).unwrap() {
        Op::Byte { value } => {
            if sp >= input.len() || *value != input[sp] {
                return Results {
                    matched: false,
                    match_number: None,
                    saved: None,
                };
            };
            recursive_backtracking_helper(cache, prog, input, pc + 1, sp + 1, saved)
        }
        Op::MaskedByte { mask, value } => {
            if sp >= input.len() || *value != (input[sp] & *mask) {
                return Results {
                    matched: false,
                    match_number: None,
                    saved: None,
                };
            };
            recursive_backtracking_helper(cache, prog, input, pc + 1, sp + 1, saved)
        }
        Op::ByteMultiNonconsuming { value } => {
            if sp >= input.len() || !value.contains(&input[sp]) {
                return Results {
                    matched: false,
                    match_number: None,
                    saved: None,
                };
            };
            recursive_backtracking_helper(cache, prog, input, pc + 1, sp, saved)
        }
        Op::Match { match_number } => {
            if sp > input.len() {
                Results {
                    matched: false,
                    match_number: None,
                    saved: None,
                }
            } else {
                Results {
                    matched: true,
                    match_number: Some(*match_number),
                    saved: Some(saved.clone()),
                }
            }
        }
        Op::Jmp { dest } => recursive_backtracking_helper(cache, prog, input, *dest, sp, saved),
        Op::Split { dest1, dest2 } => {
            let first_result = recursive_backtracking_helper(cache, prog, input, *dest1, sp, saved);
            if first_result.matched {
                return first_result;
            }
            recursive_backtracking_helper(cache, prog, input, *dest2, sp, saved)
        }
        Op::SplitMulti { dests } => {
            for dest in dests {
                let first_result =
                    recursive_backtracking_helper(cache, prog, input, *dest, sp, saved);
                if first_result.matched {
                    return first_result;
                }
            }
            Results {
                matched: false,
                match_number: None,
                saved: None,
            }
        }
        Op::SaveStart => {
            let restore = saved.start;
            saved.start = Some(sp);
            let try_result = recursive_backtracking_helper(cache, prog, input, pc + 1, sp, saved);
            if try_result.matched {
                return try_result;
            }
            saved.start = restore;

            Results {
                matched: false,
                match_number: None,
                saved: None,
            }
        }
        Op::Save { slot } => {
            let mut restore: Option<usize> = None;
            if let Some(x) = saved.captures.get(slot) {
                restore = Some(*x);
            }
            saved.captures.insert(*slot, sp);
            let try_result = recursive_backtracking_helper(cache, prog, input, pc + 1, sp, saved);
            if try_result.matched {
                return try_result;
            }
            if let Some(o) = restore {
                // Restore previous version
                saved.captures.insert(*slot, o);
            }
            Results {
                matched: false,
                match_number: None,
                saved: None,
            }
        }
        Op::Label { value } => {
            // TODO: Check if label is already set and abort matching if current value we'd be setting here is not the same as what it already is.

            let mut restore: Option<i128> = None;
            if let Some(x) = saved.labels.get(value) {
                restore = Some(*x);
            }
            saved.labels.insert(value.clone(), sp.try_into().unwrap());
            let try_result = recursive_backtracking_helper(cache, prog, input, pc + 1, sp, saved);
            if try_result.matched {
                return try_result;
            }
            if let Some(o) = restore {
                // Restore previous version
                saved.labels.insert(value.clone(), o);
            }
            Results {
                matched: false,
                match_number: None,
                saved: None,
            }
        }
        Op::AnyByte => recursive_backtracking_helper(cache, prog, input, pc + 1, sp + 1, saved),
        Op::AnyByteSequence { min, max, interval } => {
            let local_result = (*min..(*max + 1)).step_by(*interval).find_map(|i| {
                match recursive_backtracking_helper(cache, prog, input, pc + 1, sp + i, saved) {
                    Results {
                        matched: true,
                        match_number,
                        saved,
                    } => Some(Results {
                        matched: true,
                        match_number,
                        saved,
                    }),
                    _ => None,
                }
            });
            match local_result {
                Some(r) => r,
                None => Results {
                    matched: false,
                    match_number: None,
                    saved: None,
                },
            }
        }
        Op::Lookup { data } | Op::LookupQuick { bytes: _, data } => {
            for v in data {
                if sp < input.len() {
                    let result = v.do_lookup_with_saved_state(
                        cache,
                        &input.get_range(sp..),
                        &prog.tables,
                        saved,
                    );
                    if let Ok(good_result) = result {
                        return recursive_backtracking_helper(
                            cache,
                            prog,
                            input,
                            pc + 1,
                            sp + good_result.size,
                            saved,
                        );
                    }
                }
            }
            Results {
                matched: false,
                match_number: None,
                saved: None,
            }
        }
        Op::NegativeLookahead { pattern } => {
            // If our sub-pattern doesn't match, continue to the next
            // step. If it did match, then we'll stop processing this
            // thread without adding a next state
            if !run_program(10, pattern, &input.get_range(sp..)).matched {
                return recursive_backtracking_helper(cache, prog, input, pc + 1, sp, saved);
            }
            Results {
                matched: false,
                match_number: None,
                saved: None,
            }
        }
    }
    // Results {
    //     matched: false,
    //     saved: None,
    // }
}
