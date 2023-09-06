//! Normally a [pikevm](crate::automata::pikevm) only has to care about a list
//! of threads for the current byte/char and the next byte/char (as described in
//! these articles: https://swtch.com/~rsc/regexp/). However, since we have
//! operations which consume and arbitrary number of bytes, we may need to save
//! a thread such that it'll be executed some number of bytes ahead. These data
//! structures do this.
//!
//! Because this is is such a performance bottleneck, we've iterated through
//! several implementations as we work to find which works best.

// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

use alloc::vec::Vec;
use core::fmt::Debug;

use super::thread::Thread;

mod states_hash;
pub use states_hash::*;
mod states_ring;
pub use states_ring::*;
mod states_ring_rc;
pub use states_ring_rc::*;
mod states_ring_rc_ring;
pub use states_ring_rc_ring::*;
mod states_ring_rc_fixed;
pub use states_ring_rc_fixed::*;
mod states_ring_rc_fixed_unique;
pub use states_ring_rc_fixed_unique::*;
mod states_ring_rc_fixed_ring;
pub use states_ring_rc_fixed_ring::*;
mod states_ring_rc_fixed_unique_ring;
pub use states_ring_rc_fixed_unique_ring::*;

/// This trait is implemented by the modules listed above, except for the fact
/// that since [StatesRingRc] uses [ThreadRc](crate::thread::ThreadRc) it can't
/// directly implement this trait (though it does mirror it as much as it can)
pub trait States: Debug {
    fn new() -> Self;

    fn add(&mut self, sp: usize, t: Thread);

    fn get_len(&self, sp: usize) -> usize;

    fn get_states(&mut self, sp: usize) -> Option<&mut Vec<Thread>>;

    fn get_thread(&mut self, sp: usize, idx: usize) -> Option<Thread>;

    fn get_next_thread(&mut self, sp: usize) -> Option<Thread>;

    fn clear_old_states(&mut self, sp: usize);
}

pub trait StatesRc<T: Default + Sized + Clone + Debug + PartialEq>: Debug + Clone {
    fn new() -> Self;

    fn add(&mut self, sp: usize, t: T);

    fn get_next_thread(&mut self, sp: usize) -> Option<T>;

    fn clear_old_states(&mut self, sp: usize);
}
