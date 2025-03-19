//! Improves upon the [StatesRing](crate::states::states_ring::StatesRing)
//! structure. Rather than each thread containing a full copy of saved indexes
//! and variables, we use [ThreadRc] to instead keep references to this saved
//! data and only make copies when it changes.
//!
//! This has almost the same API as [States](crate::states::States) but because
//! it uses [ThreadRc] rather than [Thread](crate::thread::Thread) we can't use
//! the same trait.
//!
//! This is improved upon by
//! [StatesRingRcFixed](crate::states::states_ring_rc_fixed::StatesRingRcFixed)

// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt::Debug;

use super::StatesRc;

#[derive(Debug, Clone)]
pub struct StatesRingRc<T: Default + Sized + Clone + Debug + PartialEq> {
    inner: VecDeque<Vec<T>>,
    start_idx: usize,
}

impl<T: Default + Sized + Clone + Debug + PartialEq> StatesRc<T> for StatesRingRc<T> {
    fn new() -> Self {
        Self {
            // TODO: Give an option to make this dynamically larger from the
            // start
            inner: VecDeque::with_capacity(10),
            start_idx: 0,
        }
    }

    fn add(&mut self, sp: usize, t: T) {
        // eprintln!("Adding {} to: {:?}", sp, self);
        let sp_index = sp - self.start_idx;
        // TODO: Should make sure we don't insert duplicate threads
        let v = match self.inner.get_mut(sp_index) {
            Some(x) => x,
            None => {
                self.inner.reserve(sp_index - self.inner.len() + 200);
                while self.inner.len() <= sp_index {
                    self.inner.push_back(Vec::with_capacity(4))
                }
                self.inner.get_mut(sp_index).unwrap()
            }
        };
        // eprintln!("__________\n{} - {:?}", sp, v);
        // eprintln!("{} -  {:?}", sp, t);

        // TODO: Do the following (but don't hash every time and don't panic, just don't push)
        // let t_hash = calculate_hash(&t);
        // if v.iter().find(|x| calculate_hash(*x) == t_hash).is_some() {
        //     panic!("DUPLICATE!!!!!");
        // }
        v.push(t);
    }

    fn get_next_thread(&mut self, sp: usize) -> Option<T> {
        let x = self.inner.get_mut(sp - self.start_idx)?;
        // TODO: By pop-ing here rather than reading off the start of the list
        // we're messing with match priority. See also the notes on this page:
        // https://swtch.com/~rsc/regexp/regexp2.html starting with: "The pikevm
        // implementation given above does not completely respect thread
        // priority,"
        x.pop()
    }

    fn clear_old_states(&mut self, sp: usize) {
        // eprintln!("Clearing {} from: {:?}", sp, self);
        if sp == self.start_idx {
            if let Some(x) = self.inner.pop_front() {
                assert!(
                    x.is_empty(),
                    "Just cleared {} from \n{:x?}\nbut it had a length: {:x?}",
                    sp,
                    self.inner,
                    x
                );
            }
            self.start_idx += 1;
        }
    }
}

impl<T: Default + Sized + Clone + Debug + PartialEq> Default for StatesRingRc<T> {
    fn default() -> Self {
        Self::new()
    }
}
