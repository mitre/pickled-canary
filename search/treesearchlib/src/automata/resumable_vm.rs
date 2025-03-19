// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use core::clone::Clone;
extern crate test;

use bitvec::prelude::*;

use crate::automata::results::*;
use crate::automata::thread::ThreadRc;
use crate::bitstructs::{AddressedBits, Pattern};

use super::states::StatesRc;

pub trait ResumableVm<Endian: BitOrder + Clone + PartialEq, State: StatesRc<ThreadRc>> {
    fn new(program: Pattern<Endian>, max_cache_size: usize) -> Self;

    fn start(&mut self, input: &AddressedBits);

    /// Step through binary and get next result. This continues from any
    /// previous calls to this method. This means that the next match returned
    /// from this function may start at an earlier address than previously
    /// returned matches (since it finishes after the previously matched result)
    // #[cfg_attr(test, mutate)]
    fn search(&mut self, input: &AddressedBits) -> Results;
}
