//! This is the simplest (and worst performing) [States] structure. It uses a
//! hash to map between byte number and a list of threads to be processed for
//! that byte.
//!
//! [crate::states::states_ring] improves upon this.

// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use alloc::vec;
use alloc::vec::Vec;

use hashbrown::HashMap;

use crate::automata::states::States;
use crate::automata::thread::Thread;

#[derive(Debug)]
pub struct StatesHash {
    inner: HashMap<usize, Vec<Thread>>,
}

// fn calculate_hash<T: Hash>(t: &T) -> u64 {
//     let mut s = DefaultHasher::new();
//     t.hash(&mut s);
//     s.finish()
// }

impl States for StatesHash {
    fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    fn add(&mut self, sp: usize, t: Thread) {
        // TODO: Should make sure we don't insert duplicate threads
        let v = match self.inner.get_mut(&sp) {
            Some(x) => x,
            None => {
                self.inner.insert(sp, Vec::with_capacity(4));
                self.inner.get_mut(&sp).unwrap()
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
        match self.inner.get(&sp) {
            Some(x) => x.len(),
            None => 0,
        }
    }

    fn get_states(&mut self, sp: usize) -> Option<&mut Vec<Thread>> {
        self.inner.get_mut(&sp)
    }

    fn get_thread(&mut self, sp: usize, idx: usize) -> Option<Thread> {
        Some(self.inner.get_mut(&sp)?.get_mut(idx).unwrap().clone())
    }
    fn get_next_thread(&mut self, sp: usize) -> Option<Thread> {
        let x = self.inner.get_mut(&sp)?;
        // TODO: By pop-ing here rather than reading off the start of the list
        // we're messing with match priority. See also the notes on this page:
        // https://swtch.com/~rsc/regexp/regexp2.html starting with: "The pikevm
        // implementation given above does not completely respect thread
        // priority,"
        // eprintln!("{:#?}", x);
        let out = x.pop();

        // Remove hash entry if there's nothing left in the vec. This makes
        // adding to and searching the hash much faster.
        if x.is_empty() {
            self.inner.remove(&sp);
        }
        out
    }

    fn clear_old_states(&mut self, sp: usize) {
        self.inner.insert(sp, vec![]);
    }
}
