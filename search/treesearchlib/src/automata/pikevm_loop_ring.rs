//! This improvement simply combines the improvements found in
//! [crate::automata::pikevm_loop] and [crate::automata::pikevm_ring]
//!
//! The next improvement is in [crate::automata::pikevm_loop_ring_rc]

// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

use core::clone::Clone;
extern crate test;

use bitvec::prelude::*;

use crate::automata::pikevm_loop::pikevm_inner_loop;
use crate::automata::results::*;
use crate::automata::states::{States, StatesRing};
use crate::bitstructs::{AddressedBits, Pattern};

pub fn run_program<Endian: BitOrder + Clone + PartialEq>(
    max_cache_size: usize,
    prog: &Pattern<Endian>,
    input: &AddressedBits,
) -> Results {
    let mut states = StatesRing::new();
    pikevm_inner_loop(max_cache_size, prog, input, &mut states)
}
