//! This improvement builds off of
//! [pikevm_loop_ring_rc_fixed](crate::automata::pikevm_loop_ring_rc_fixed).
//!
//! This was an experiment with not using a cache... turns out for random input
//! data a cache performs more or less the same as no cache
//!
//! This is currently the most-optimized automata

// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::clone::Clone;
use core::convert::TryInto;
extern crate test;

use bitvec::prelude::*;

use crate::automata::results::*;
use crate::automata::thread::{SavedData, ThreadRc};
use crate::bitstructs::{AddressedBits, LookupCache, Op, Pattern};

use super::resumable_vm::ResumableVm;
use super::states::StatesRc;

// The following two lines can be uncommented (along with the corrisponding
// function annotations) to enable mutation testing using the mutagen crate
// (which also must be uncommented in Cargo.toml). These lines are not left in
// because they cause lots of red with Cargo-analyzer's VSCode configuration
// (although they seem to work fine otherwise)

// #[cfg(test)] use
// mutagen::mutate;

struct NextThreadData {
    sp_next: usize,
    pc: usize,
    clone_saved: bool,
    set_start: bool,
}

/// This rather verbose technique is used to try as hard as we can to not have
/// to create a vec (which is slow because of allocation/free time)
enum NextThreadsData {
    None,
    One(NextThreadData),
    Two([NextThreadData; 2]),
    Three([NextThreadData; 3]),
    Four([NextThreadData; 4]),
    Five([NextThreadData; 5]),
    Six([NextThreadData; 6]),
    More(Vec<NextThreadData>),
}

pub struct PikevmLoopRingRcPriority<Endian: BitOrder + Clone + PartialEq, State: StatesRc<ThreadRc>>
{
    program: Pattern<Endian>,
    states: State,
    sp: usize,
    cache: LookupCache<Endian>,
}

impl<Endian: BitOrder + Clone + PartialEq, State: StatesRc<ThreadRc>> ResumableVm<Endian, State>
    for PikevmLoopRingRcPriority<Endian, State>
{
    fn new(program: Pattern<Endian>, max_cache_size: usize) -> Self {
        Self {
            program,
            states: State::new(),
            sp: 0,
            cache: LookupCache::new(max_cache_size),
        }
    }

    fn start(&mut self, input: &AddressedBits) {
        self.add_thread(0, 0, input, &mut Rc::new(SavedData::default()), None);
    }

    /// Step through binary and get next result. This continues from any
    /// previous calls to this method. This means that the next match returned
    /// from this function may start at an earlier address than previously
    /// returned matches (since it finishes after the previously matched result)
    // #[cfg_attr(test, mutate)]
    fn search(&mut self, input: &AddressedBits) -> Results {
        while self.sp <= input.len() {
            // eprintln!("{}->{}", input.len(), self.sp);
            // eprintln!("States: {:?}", states);

            loop {
                let option_next_thread = self.states.get_next_thread(self.sp);
                if option_next_thread.is_none() {
                    break;
                }
                let mut t = option_next_thread.unwrap();
                // eprintln!("Pulled thread: pc={} at self.sp {}", t.pc_idx, self.sp);

                if let Some(x) = self.process_thread_rc(&mut t, input) {
                    return x;
                }
                // eprintln!("After States: {:?}", states);
            }
            self.states.clear_old_states(self.sp);
            self.sp += 1;
        }

        Results {
            matched: false,
            match_number: None,
            saved: None,
        }
    }
}

impl<Endian: BitOrder + Clone + PartialEq, State: StatesRc<ThreadRc>>
    PikevmLoopRingRcPriority<Endian, State>
{
    fn add_thread(
        &mut self,
        sp_next: usize,
        pc: usize,
        input: &AddressedBits,
        saved: &mut Rc<SavedData>,
        start: Option<usize>,
    ) {
        let current_step = self.program.steps.get(pc).unwrap();
        let add_thread_args = match current_step {
            Op::ByteMultiNonconsuming { value } => {
                if input.len() > sp_next && value.contains(&input[sp_next]) {
                    NextThreadsData::One(NextThreadData {
                        sp_next,
                        pc: pc + 1,
                        clone_saved: false,
                        set_start: false,
                    })
                } else {
                    NextThreadsData::None
                }
            }
            Op::Jmp { dest } => NextThreadsData::One(NextThreadData {
                sp_next,
                pc: *dest,
                clone_saved: false,
                set_start: false,
            }),
            Op::Split { dest1, dest2 } => NextThreadsData::Two([
                NextThreadData {
                    sp_next,
                    pc: *dest1,
                    clone_saved: true,
                    set_start: false,
                },
                NextThreadData {
                    sp_next,
                    pc: *dest2,
                    clone_saved: true,
                    set_start: false,
                },
            ]),
            Op::SplitMulti { dests } => match dests.len() {
                0 => panic!("Cannot have an empty SplitMulti!"),
                1 => NextThreadsData::One(NextThreadData {
                    sp_next,
                    pc: dests[0],
                    clone_saved: true,
                    set_start: false,
                }),
                2 => NextThreadsData::Two([
                    NextThreadData {
                        sp_next,
                        pc: dests[0],
                        clone_saved: true,
                        set_start: false,
                    },
                    NextThreadData {
                        sp_next,
                        pc: dests[1],
                        clone_saved: true,
                        set_start: false,
                    },
                ]),
                3 => NextThreadsData::Three([
                    NextThreadData {
                        sp_next,
                        pc: dests[0],
                        clone_saved: true,
                        set_start: false,
                    },
                    NextThreadData {
                        sp_next,
                        pc: dests[1],
                        clone_saved: true,
                        set_start: false,
                    },
                    NextThreadData {
                        sp_next,
                        pc: dests[2],
                        clone_saved: true,
                        set_start: false,
                    },
                ]),
                4 => NextThreadsData::Four([
                    NextThreadData {
                        sp_next,
                        pc: dests[0],
                        clone_saved: true,
                        set_start: false,
                    },
                    NextThreadData {
                        sp_next,
                        pc: dests[1],
                        clone_saved: true,
                        set_start: false,
                    },
                    NextThreadData {
                        sp_next,
                        pc: dests[2],
                        clone_saved: true,
                        set_start: false,
                    },
                    NextThreadData {
                        sp_next,
                        pc: dests[3],
                        clone_saved: true,
                        set_start: false,
                    },
                ]),
                5 => NextThreadsData::Five([
                    NextThreadData {
                        sp_next,
                        pc: dests[0],
                        clone_saved: true,
                        set_start: false,
                    },
                    NextThreadData {
                        sp_next,
                        pc: dests[1],
                        clone_saved: true,
                        set_start: false,
                    },
                    NextThreadData {
                        sp_next,
                        pc: dests[2],
                        clone_saved: true,
                        set_start: false,
                    },
                    NextThreadData {
                        sp_next,
                        pc: dests[3],
                        clone_saved: true,
                        set_start: false,
                    },
                    NextThreadData {
                        sp_next,
                        pc: dests[4],
                        clone_saved: true,
                        set_start: false,
                    },
                ]),
                6 => NextThreadsData::Six([
                    NextThreadData {
                        sp_next,
                        pc: dests[0],
                        clone_saved: true,
                        set_start: false,
                    },
                    NextThreadData {
                        sp_next,
                        pc: dests[1],
                        clone_saved: true,
                        set_start: false,
                    },
                    NextThreadData {
                        sp_next,
                        pc: dests[2],
                        clone_saved: true,
                        set_start: false,
                    },
                    NextThreadData {
                        sp_next,
                        pc: dests[3],
                        clone_saved: true,
                        set_start: false,
                    },
                    NextThreadData {
                        sp_next,
                        pc: dests[4],
                        clone_saved: true,
                        set_start: false,
                    },
                    NextThreadData {
                        sp_next,
                        pc: dests[5],
                        clone_saved: true,
                        set_start: false,
                    },
                ]),
                _ => NextThreadsData::More(
                    dests[..]
                        .iter()
                        .map(|dest| NextThreadData {
                            sp_next,
                            pc: *dest,
                            clone_saved: true,
                            set_start: false,
                        })
                        .collect(),
                ),
            },
            Op::SaveStart => NextThreadsData::One(NextThreadData {
                sp_next,
                pc: pc + 1,
                clone_saved: false,
                set_start: true,
            }),
            Op::Save { slot } => {
                // let saved_ready_to_mut = Rc::make_mut(saved);

                // saved_ready_to_mut.captures.insert(*slot, sp);
                // // dd(Thread::new(pc + 1, &saved));
                // *saved = Rc::new(saved_ready_to_mut.clone());
                Rc::make_mut(saved).captures.insert(*slot, sp_next);
                NextThreadsData::One(NextThreadData {
                    sp_next,
                    pc: pc + 1,
                    clone_saved: false,
                    set_start: false,
                })
            }
            Op::Label { value } => {
                let this_label_value = TryInto::<i128>::try_into(sp_next).unwrap()
                    + i128::from(input.get_base_address());
                if let Some(existing_value) = saved.labels.get(value) {
                    if *existing_value != this_label_value {
                        return;
                    }
                } else {
                    Rc::make_mut(saved)
                        .labels
                        .insert(value.clone(), this_label_value);
                }
                NextThreadsData::One(NextThreadData {
                    sp_next,
                    pc: pc + 1,
                    clone_saved: false,
                    set_start: false,
                })
            }
            _ => {
                self.states.add(sp_next, ThreadRc::new(pc, saved, start));
                NextThreadsData::None
            }
        };

        // We're doing a bit of a silly here... Rust (currently) isn't smart
        // enough to recognize that our reference to self in the match statement
        // doesn't interfere with a call to self.add_thread despite the latter
        // being a mutable reference and the match being a non-mutable
        // reference. So... we just create a list of vec of the threads we need
        // to create and then call add_thread here. This is a performance bummer
        // to be sure, but it's better than cloning the current step in the
        // match statement.
        //
        // We're also very careful here to not create a vec unless we REALLY
        // need too (because creating and freeing the memory for a vec is slow)
        match add_thread_args {
            NextThreadsData::None => {}
            NextThreadsData::One(next_thread_data) => {
                self.add_thread_helper(&next_thread_data, sp_next, start, input, saved)
            }
            NextThreadsData::Two(n) => {
                self.add_thread_helper(&n[0], sp_next, start, input, saved);
                self.add_thread_helper(&n[1], sp_next, start, input, saved);
            }
            NextThreadsData::Three(n) => {
                self.add_thread_helper(&n[0], sp_next, start, input, saved);
                self.add_thread_helper(&n[1], sp_next, start, input, saved);
                self.add_thread_helper(&n[2], sp_next, start, input, saved);
            }
            NextThreadsData::Four(n) => {
                self.add_thread_helper(&n[0], sp_next, start, input, saved);
                self.add_thread_helper(&n[1], sp_next, start, input, saved);
                self.add_thread_helper(&n[2], sp_next, start, input, saved);
                self.add_thread_helper(&n[3], sp_next, start, input, saved);
            }
            NextThreadsData::Five(n) => {
                self.add_thread_helper(&n[0], sp_next, start, input, saved);
                self.add_thread_helper(&n[1], sp_next, start, input, saved);
                self.add_thread_helper(&n[2], sp_next, start, input, saved);
                self.add_thread_helper(&n[3], sp_next, start, input, saved);
                self.add_thread_helper(&n[4], sp_next, start, input, saved);
            }
            NextThreadsData::Six(n) => {
                // TODO: Determine if this is more or less optimized by the compiler than a for_each over n
                self.add_thread_helper(&n[0], sp_next, start, input, saved);
                self.add_thread_helper(&n[1], sp_next, start, input, saved);
                self.add_thread_helper(&n[2], sp_next, start, input, saved);
                self.add_thread_helper(&n[3], sp_next, start, input, saved);
                self.add_thread_helper(&n[4], sp_next, start, input, saved);
                self.add_thread_helper(&n[5], sp_next, start, input, saved);
            }
            NextThreadsData::More(more) => more.iter().for_each(|a| {
                self.add_thread_helper(a, sp_next, start, input, saved);
            }),
        }
    }

    #[inline]
    fn add_thread_helper(
        &mut self,
        a: &NextThreadData,
        sp_next: usize,
        start: Option<usize>,
        input: &AddressedBits,
        saved: &mut Rc<SavedData>,
    ) {
        let next_start = if a.set_start { Some(sp_next) } else { start };
        if a.clone_saved {
            self.add_thread(a.sp_next, a.pc, input, &mut Rc::clone(saved), next_start)
        } else {
            self.add_thread(a.sp_next, a.pc, input, saved, next_start)
        }
    }

    // #[cfg_attr(test, mutate)]
    fn process_thread_rc(
        &mut self,
        thread: &mut ThreadRc,
        input: &AddressedBits,
    ) -> Option<Results> {
        let mut pc = thread.pc_idx;
        let saved = &mut thread.saved;
        let start = thread.start;
        loop {
            match self.program.steps.get(pc).unwrap() {
                Op::Byte { value } => {
                    if input.len() > self.sp && *value == input[self.sp] {
                        self.add_thread(self.sp + 1, pc + 1, input, saved, start);
                    }
                    break;
                }
                Op::MaskedByte { mask, value } => {
                    if input.len() > self.sp && *value == (input[self.sp] & *mask) {
                        self.add_thread(self.sp + 1, pc + 1, input, saved, start);
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
                    self.add_thread(self.sp + 1, pc + 1, input, saved, start);
                    break;
                }
                Op::AnyByteSequence { min, max, interval } => {
                    for i in (*min..(*max + 1)).step_by(*interval) {
                        self.add_thread(self.sp + i, pc + 1, input, saved, start);
                    }
                    break;
                }
                Op::Lookup { data } => {
                    let bits = input.get_range(self.sp..);
                    for v in data {
                        let result = v.do_lookup_with_saved_state_rc_no_cache(
                            &mut self.cache,
                            &bits,
                            &self.program.tables,
                            saved,
                        );
                        if let Ok(good_result) = result {
                            self.add_thread(
                                self.sp + good_result.size,
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
                    if input.len() > self.sp && !bytes.contains(&input[self.sp]) {
                        break;
                    }

                    let bits = input.get_range(self.sp..);
                    for v in data {
                        let result = v.do_lookup_with_saved_state_rc_no_cache(
                            &mut self.cache,
                            &bits,
                            &self.program.tables,
                            saved,
                        );
                        if let Ok(good_result) = result {
                            self.add_thread(
                                self.sp + good_result.size,
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
                    if !run_program::<Endian, State>(10, pattern, &input.get_range(self.sp..))
                        .matched
                    {
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
}

/// This will only find the first result!
pub fn run_program<Endian: BitOrder + Clone + PartialEq, State: StatesRc<ThreadRc>>(
    max_cache_size: usize,
    prog: &Pattern<Endian>,
    input: &AddressedBits,
) -> Results {
    let mut vm: PikevmLoopRingRcPriority<Endian, State> =
        PikevmLoopRingRcPriority::new(prog.clone(), max_cache_size);

    vm.start(input);
    vm.search(input)
}
