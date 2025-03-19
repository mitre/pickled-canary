//! Improves upon the
//! [StatesRingRc](crate::states::states_ring_rc::StatesRingRc) by using fixed
//! size buffers (unallocated) to hold all our state. This means no mallocs /
//! frees are needed (theoretically improving speed)
//!
//! Several improvements were pursued from this version including:
//! * [StatesRingRcFixedUnique](crate::states::states_ring_rc_fixed_unique::StatesRingRcFixedUnique)
//! * [StatesRingRcFixedRing](crate::states::states_ring_rc_fixed_ring::StatesRingRcFixedRing)

// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

#[cfg(test)]
use alloc::fmt::Display;

#[cfg(test)]
use core::fmt;

use alloc::fmt::Debug;

use super::StatesRc;

#[derive(Debug, Clone)]
pub struct StatesRingRcFixed<
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
    // Each entry in this array corrisponds to the number of states currently in
    // the corrispoding array at the same index in "inner"
    lengths: [usize; STEP_COUNT],
    // This contains an array of states (the inner arrays) per step (the outer
    // array)
    inner: [[T; STATE_COUNT]; STEP_COUNT],
}

impl<
        T: Default + Sized + Clone + Debug + PartialEq,
        const STEP_COUNT: usize,
        const STATE_COUNT: usize,
    > StatesRingRcFixed<T, STEP_COUNT, STATE_COUNT>
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
    > StatesRc<T> for StatesRingRcFixed<T, STEP_COUNT, STATE_COUNT>
{
    fn new() -> Self {
        Self {
            start: 0,
            start_step: 0,
            lengths: [0; STEP_COUNT],
            // This is somewhat ugly, but it avoids us having to make T Copy
            // This might not be the most effecient, but we only do it once
            inner: [(); STEP_COUNT].map(|_| [(); STATE_COUNT].map(|_| T::default())),
        }
    }

    fn add(&mut self, sp: usize, t: T) {
        // eprintln!("Adding {} to: {:?}", sp, self);
        let sp_index = self.get_idx_for_step(sp);

        let tail = self.lengths[sp_index];
        if tail >= STATE_COUNT {
            panic!(
                "Too many states for step. Need more states in states_ring_rc_fixed: {:#?}",
                self.inner[sp_index]
            );
        }

        self.inner[sp_index][tail] = t;
        self.lengths[sp_index] += 1;
    }

    fn get_next_thread(&mut self, sp: usize) -> Option<T> {
        // TODO: By pop-ing here rather than reading off the start of the list
        // we're messing with match priority. See also the notes on this page:
        // https://swtch.com/~rsc/regexp/regexp2.html starting with: "The pikevm
        // implementation given above does not completely respect thread
        // priority,"
        let sp_index = self.get_idx_for_step(sp);

        if self.lengths[sp_index] > 0 {
            let tail = self.lengths[sp_index] - 1;
            let out = self.inner[sp_index][tail].clone();
            self.lengths[sp_index] = tail;
            Some(out)
        } else {
            None
        }
    }

    fn clear_old_states(&mut self, sp: usize) {
        // // eprintln!("Clearing {} from: {:?}", sp, self);
        if sp == self.start_step {
            let sp_index = self.get_idx_for_step(sp);

            if self.lengths[sp_index] != 0 {
                panic!(
                    "Just cleared {} from \n{:x?}\nbut it had a length: {:x?}",
                    sp, self.inner, self.lengths[sp_index]
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
    > Default for StatesRingRcFixed<T, STEP_COUNT, STATE_COUNT>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl<
        T: Default + Sized + Clone + Debug + PartialEq,
        const STEP_COUNT: usize,
        const STATE_COUNT: usize,
    > Display for StatesRingRcFixed<T, STEP_COUNT, STATE_COUNT>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}@{} -> ", self.start_step, self.start)?;
        for step_offset in 0..(STEP_COUNT - 1) {
            write!(f, "{}: ", self.start_step + step_offset)?;
            let step_idx = self.get_idx_for_step(self.start_step + step_offset);
            for state_idx in 0..self.lengths[step_idx] {
                write!(f, "{:?}, ", self.inner[step_idx][state_idx])?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idx() {
        let mut test: StatesRingRcFixed<usize, 10, 10> = StatesRingRcFixed::new();
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
        let test: StatesRingRcFixed<usize, 10, 10> = StatesRingRcFixed::new();
        assert_eq!(test.get_idx_for_step(11), 0);
    }

    #[test]
    fn test_add() {
        let mut test: StatesRingRcFixed<usize, 10, 10> = StatesRingRcFixed::new();
        test.start_step = 10;
        test.add(13, 7);
        test.add(13, 8);
        let mut expected: [usize; 10] = [0; 10];
        expected[0] = 7;
        expected[1] = 8;
        assert_eq!(test.inner[3], expected);
    }

    #[test]
    fn test_get_next_thread() {
        let mut test: StatesRingRcFixed<usize, 10, 10> = StatesRingRcFixed::new();
        test.start_step = 10;
        test.add(13, 7);
        test.add(13, 8);
        assert_eq!(test.get_next_thread(13), Some(8));
        assert_eq!(test.get_next_thread(13), Some(7));
        assert_eq!(test.get_next_thread(14), None);
    }
    #[test]
    fn test_clear_old_states() {
        let mut test: StatesRingRcFixed<usize, 10, 10> = StatesRingRcFixed::new();
        test.start_step = 10;
        test.add(13, 7);
        test.add(13, 8);
        test.clear_old_states(13);
        test.clear_old_states(10);
        test.clear_old_states(11);
        test.clear_old_states(12);
        assert_eq!(test.get_next_thread(13), Some(8));
        assert_eq!(test.get_next_thread(13), Some(7));
        assert_eq!(test.get_next_thread(14), None);
    }
}
