//! Improves upon the
//! [StatesRingRcFixed](crate::states::states_ring_rc_fixed::StatesRingRcFixed)
//! by using a fixed ring buffer for the individual step's states so that states
//! are processed in the correct order (preservinig OR priority)

// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

#[cfg(test)]
use core::fmt;

use alloc::fmt::Debug;

use super::StatesRc;

#[derive(Clone, Copy)]
#[cfg_attr(not(test), derive(Debug))]
struct FixedVecDeque<T: Default + Sized + Clone + Debug + PartialEq, const STATE_COUNT: usize> {
    start: usize,
    length: usize,
    inner: [T; STATE_COUNT],
}

impl<T: Default + Sized + Clone + Debug + PartialEq, const STATE_COUNT: usize>
    FixedVecDeque<T, STATE_COUNT>
{
    #[inline]
    fn get_idx_for_idx(&self, in_index: usize) -> usize {
        if in_index >= self.inner.len() {
            panic!("Index out of range. Need more steps in states_ring_rc_fixed_unique_ring");
        }
        (self.start + in_index) % (self.inner.len())
    }

    fn add(&mut self, input: T) {
        // TODO: implemnt the following (will require moving away from generic T)

        // // Dont add this state if we have a matching (except start #) one with a
        // // lower start
        // let almost_duplicates = self.inner[..self.length]
        //     .iter()
        //     .filter(|x| *x.eq_ignoring_start(t));
        // if almost_duplicates.len() > 0 && !almost_duplicates.all(|x| x.start > t.start) {
        //     return;
        // }

        self.inner[self.get_idx_for_idx(self.length)] = input;
        self.length += 1;
    }

    fn pop_front(&mut self) -> Option<T> {
        if self.length > 0 {
            let out = self.inner[self.start].clone();
            self.start = self.get_idx_for_idx(1);
            self.length -= 1;
            Some(out)
        } else {
            None
        }
    }
}

#[cfg(test)]
impl<T: Default + Sized + Clone + Debug + PartialEq, const STATE_COUNT: usize>
    From<&FixedVecDeque<T, STATE_COUNT>> for Vec<T>
{
    fn from(input: &FixedVecDeque<T, STATE_COUNT>) -> Vec<T> {
        let mut out = Vec::new();
        for idx in 0..input.length {
            out.push(input.inner[input.get_idx_for_idx(idx)].clone());
        }
        out
    }
}

#[cfg(test)]
impl<T: Default + Sized + Clone + Debug + PartialEq, const STATE_COUNT: usize> Debug
    for FixedVecDeque<T, STATE_COUNT>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let as_vec: Vec<T> = self.into();
        if !as_vec.is_empty() {
            write!(f, "{{")?;
            f.debug_list().entries(as_vec).finish()?;
            write!(f, "}}")
        } else {
            write!(f, "{{}}")
        }
    }
}

impl<T: Default + Sized + Clone + Debug + PartialEq, const STATE_COUNT: usize> Default
    for FixedVecDeque<T, STATE_COUNT>
{
    fn default() -> Self {
        Self {
            start: 0,
            length: 0,
            inner: [(); STATE_COUNT].map(|_| T::default()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StatesRingRcFixedRing<
    T: Default + Sized + Clone + Debug + PartialEq,
    const STEP_COUNT: usize,
    const STATE_COUNT: usize,
> {
    // inner is treated like a ring buffer... this is the pointer to that
    // buffer's start (as an index into "inner")
    start: usize,
    // This records the step number that the index held in "start" corrisponds
    // to
    start_step: usize,
    // This contains an array of states (the inner arrays) per step (the outer
    // array)
    inner: [FixedVecDeque<T, STATE_COUNT>; STEP_COUNT],
}
impl<
        T: Default + Sized + Clone + Debug + PartialEq,
        const STEP_COUNT: usize,
        const STATE_COUNT: usize,
    > StatesRingRcFixedRing<T, STEP_COUNT, STATE_COUNT>
{
    #[inline]
    fn get_idx_for_step(&self, step: usize) -> usize {
        let offset = step - self.start_step;
        if offset >= self.inner.len() {
            panic!("Index out of range. Need more steps in states_ring_rc_fixed");
        }
        (self.start + offset) % (self.inner.len())
    }
}

impl<
        T: Default + Sized + Clone + Debug + PartialEq,
        const STEP_COUNT: usize,
        const STATE_COUNT: usize,
    > StatesRc<T> for StatesRingRcFixedRing<T, STEP_COUNT, STATE_COUNT>
{
    fn new() -> Self {
        Self {
            start: 0,
            start_step: 0,
            // This is somewhat ugly, but it avoids us having to make T Copy
            // This might not be the most effecient, but we only do it once
            inner: [(); STEP_COUNT].map(|_| FixedVecDeque::default()),
        }
    }

    fn add(&mut self, sp: usize, t: T) {
        // eprintln!("Adding {} to: {:?}", sp, self);
        let sp_index = self.get_idx_for_step(sp);

        self.inner[sp_index].add(t);
    }

    fn get_next_thread(&mut self, sp: usize) -> Option<T> {
        let sp_index = self.get_idx_for_step(sp);

        self.inner[sp_index].pop_front()
    }

    fn clear_old_states(&mut self, sp: usize) {
        // // eprintln!("Clearing {} from: {:?}", sp, self);
        if sp == self.start_step {
            let sp_index = self.get_idx_for_step(sp);

            if self.inner[sp_index].length != 0 {
                panic!(
                    "Just cleared {} from \n{:x?}\nbut it had a length: {:x?}",
                    sp, self.inner, self.inner[sp_index].length
                );
            }
            let new_start = self.get_idx_for_step(self.start_step + 1);
            self.start_step += 1;
            self.start = new_start;
        }
    }
}

impl<
        T: Default + Sized + Clone + Debug + PartialEq,
        const STEP_COUNT: usize,
        const STATE_COUNT: usize,
    > Default for StatesRingRcFixedRing<T, STEP_COUNT, STATE_COUNT>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idx() {
        let mut test: StatesRingRcFixedRing<usize, 10, 10> = StatesRingRcFixedRing::new();
        assert_eq!(test.get_idx_for_step(0), 0);
        assert_eq!(test.get_idx_for_step(4), 4);

        test.start_step = 55;
        assert_eq!(test.get_idx_for_step(56), 1);
        assert_eq!(test.get_idx_for_step(60), 5);

        test.start = 8;
        assert_eq!(test.get_idx_for_step(56), 9);
        assert_eq!(test.get_idx_for_step(60), 3);
    }
    #[test]
    #[should_panic]
    fn test_idx_panic() {
        let test: StatesRingRcFixedRing<usize, 10, 10> = StatesRingRcFixedRing::new();
        assert_eq!(test.get_idx_for_step(11), 0);
    }

    #[test]
    fn test_add() {
        let mut test: StatesRingRcFixedRing<usize, 10, 10> = StatesRingRcFixedRing::new();
        test.start_step = 10;
        test.add(13, 7);
        test.add(13, 8);

        assert_eq!(test.inner[test.get_idx_for_step(13)].pop_front(), Some(7));
        assert_eq!(test.inner[test.get_idx_for_step(13)].pop_front(), Some(8));
    }

    #[test]
    fn test_get_next_thread() {
        let mut test: StatesRingRcFixedRing<usize, 10, 10> = StatesRingRcFixedRing::new();
        test.start_step = 10;
        test.add(13, 7);
        test.add(13, 8);
        assert_eq!(test.get_next_thread(13), Some(7));
        assert_eq!(test.get_next_thread(13), Some(8));
        assert_eq!(test.get_next_thread(14), None);
    }
    #[test]
    fn test_clear_old_states() {
        let mut test: StatesRingRcFixedRing<usize, 10, 10> = StatesRingRcFixedRing::new();
        test.start_step = 10;
        test.add(13, 7);
        test.add(13, 8);
        // This shouldn't do anything because it's not the start_step
        test.clear_old_states(13);
        // These will clear things
        test.clear_old_states(10);
        test.clear_old_states(11);
        test.clear_old_states(12);
        assert_eq!(test.get_next_thread(13), Some(7));
        assert_eq!(test.get_next_thread(13), Some(8));
        assert_eq!(test.get_next_thread(14), None);
        test.clear_old_states(13);
        assert_eq!(test.start_step, 14);
    }

    #[test]
    #[should_panic]
    fn test_clear_old_states_panic() {
        let mut test: StatesRingRcFixedRing<usize, 10, 10> = StatesRingRcFixedRing::new();
        test.start_step = 10;
        test.add(10, 7);
        // This should panic because there's a state in there
        test.clear_old_states(10);
    }
}
