//! Improves upon the [StatesHash](crate::states::states_hash) structure.
//! Instead of using a hashmap, this uses a ring buffer and we keep track of the
//! starting byte index of our ring buffer. By using a ring buffer we avoid
//! having reallocate and/or shift when we pop an item from the start of the
//! list. By keeping track of our starting index, we remove the need for
//! constant hashing to determine which index we need to update (simple math
//! works intead).
//!
//! [states_ring](crate::states::states_ring_rc) improves upon this.

// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::automata::states::States;
use crate::automata::thread::Thread;

#[derive(Debug)]
pub struct StatesRing {
    // Notice, this is using a VecDeque rather than a HashMap
    inner: VecDeque<Vec<Thread>>,
    start_idx: usize,
}

impl States for StatesRing {
    fn new() -> Self {
        Self {
            // TODO: Give an option to make this dynamically larger from the
            // start
            inner: VecDeque::with_capacity(10),
            start_idx: 0,
        }
    }

    fn add(&mut self, sp: usize, t: Thread) {
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

    fn get_len(&self, sp: usize) -> usize {
        match self.inner.get(sp - self.start_idx) {
            Some(x) => x.len(),
            None => 0,
        }
    }

    fn get_states(&mut self, sp: usize) -> Option<&mut Vec<Thread>> {
        self.inner.get_mut(sp - self.start_idx)
    }

    fn get_thread(&mut self, sp: usize, idx: usize) -> Option<Thread> {
        Some(
            self.inner
                .get_mut(sp - self.start_idx)?
                .get_mut(idx)
                .unwrap()
                .clone(),
        )
    }

    fn get_next_thread(&mut self, sp: usize) -> Option<Thread> {
        let x = self.inner.get_mut(sp - self.start_idx)?;
        // TODO: By pop-ing here rather than reading off the start of the list
        // we're messing with match priority. See also the notes on this page:
        // https://swtch.com/~rsc/regexp/regexp2.html starting with: "The pikevm
        // implementation given above does not completely respect thread
        // priority,"
        x.pop()
    }

    /// To avoid having our ring buffer grow and grow, we can remove the front
    /// element when we are done with it by calling this function.
    fn clear_old_states(&mut self, sp: usize) {
        // eprintln!("Clearing {} from: {:?}", sp, self);
        if sp == self.start_idx {
            if let Some(x) = self.inner.pop_front() {
                if !x.is_empty() {
                    panic!(
                        "Just cleared {}  from \n{:x?}\nbut it had a length: {:x?}",
                        sp, self.inner, x
                    );
                }
            }
            self.start_idx += 1;
        }
    }
}

impl Default for StatesRing {
    fn default() -> Self {
        Self::new()
    }
}
