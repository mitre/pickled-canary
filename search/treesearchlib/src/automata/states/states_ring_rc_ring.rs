//! Improves upon the
//! [StatesRingRc](crate::states::states_ring_Rc::StatesRingRc) structure.
//! Instead of an inner vec, we use VecDeque so that we can pop from the front
//! easily. This preserves processing priority (which makes the correct OR block
//! match in nearly-ambiguious cases).
//!
//! This is improved upon by
//! [StatesRingRcFixedRing](crate::states::states_ring_rc_fixed_ring::StatesRingRcFixedRing)
//! although that also has lineage through
//! [StatesRingRcFixed](crate::states::states_ring_rc_fixed::StatesRingRcFixed)

// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use alloc::collections::VecDeque;
use core::fmt::Debug;

use super::StatesRc;

#[derive(Debug, Clone)]
pub struct StatesRingRcRing<T: Default + Sized + Clone + Debug + PartialEq> {
    inner: VecDeque<VecDeque<T>>,
    start_idx: usize,
}

const CAPACITY: usize = 100;
const INNER_CAPACITY: usize = 10;
impl<T: Default + Sized + Clone + Debug + PartialEq> StatesRc<T> for StatesRingRcRing<T> {
    fn new() -> Self {
        let mut inner = VecDeque::with_capacity(CAPACITY);
        for _ in 0..CAPACITY {
            inner.push_back(VecDeque::with_capacity(INNER_CAPACITY));
        }
        Self {
            // TODO: Give an option to make this dynamically larger from the
            // start
            inner,
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
                    self.inner
                        .push_back(VecDeque::with_capacity(INNER_CAPACITY))
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
        v.push_back(t);
    }

    // fn get_len(&self, sp: usize) -> usize {
    //     match self.inner.get(sp - self.start_idx) {
    //         Some(x) => x.len(),
    //         None => 0,
    //     }
    // }

    // fn get_states(&mut self, sp: usize) -> Option<&mut VecDeque<ThreadRc>> {
    //     self.inner.get_mut(sp - self.start_idx)
    // }

    // fn get_thread(&mut self, sp: usize, idx: usize) -> Option<ThreadRc> {
    //     Some(
    //         self.inner
    //             .get_mut(sp - self.start_idx)?
    //             .get_mut(idx)
    //             .unwrap()
    //             .clone(),
    //     )
    // }

    fn get_next_thread(&mut self, sp: usize) -> Option<T> {
        let x = self.inner.get_mut(sp - self.start_idx)?;
        // By pop-ing FROM THE FRONT here we are preserving match priority. See
        // also the notes on this page:
        // https://swtch.com/~rsc/regexp/regexp2.html starting with: "The pikevm
        // implementation given above does not completely respect thread
        // priority,"
        let out = x.pop_front();

        if out.is_none() {
            self.inner.rotate_left(1);
            self.start_idx += 1;
        }
        out
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

impl<T: Default + Sized + Clone + Debug + PartialEq> Default for StatesRingRcRing<T> {
    fn default() -> Self {
        Self::new()
    }
}
