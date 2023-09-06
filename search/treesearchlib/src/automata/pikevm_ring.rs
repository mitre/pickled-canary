//! This works the same as [crate::automata::pikevm] but uses a ring buffer to
//! keep track of states rather than a simple vec. This lets us do much less
//! allocating which greatly improves performance.
//!
//! The another improvement is found in [crate::automata::pikevm_loop]

// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

use core::clone::Clone;
extern crate test;

use bitvec::prelude::*;

use crate::automata::pikevm::pikevm_inner;
use crate::automata::results::*;
use crate::automata::states::{States, StatesRing};
use crate::bitstructs::{AddressedBits, Pattern};

pub fn run_program<Endian: BitOrder + Clone + PartialEq>(
    max_cache_size: usize,
    prog: &Pattern<Endian>,
    input: &AddressedBits,
) -> Results {
    let mut states = StatesRing::new();
    pikevm_inner(max_cache_size, prog, input, &mut states)
}
