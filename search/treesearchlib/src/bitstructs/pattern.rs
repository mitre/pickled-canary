// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::convert::TryInto;
use core::panic;
use hashbrown::HashMap;

use super::super::jsonstructs as j;
use super::Op;
use super::OperandValueTable;
use bitvec::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern<Endian: BitOrder + Clone> {
    pub steps: Vec<Op<Endian>>,
    pub tables: Vec<OperandValueTable<Endian>>,
}

impl<Endian: BitOrder + Clone> From<j::Pattern> for Pattern<Endian> {
    fn from(item: j::Pattern) -> Self {
        let mut out = Self {
            steps: item
                .steps
                .iter()
                .map(|x| {
                    let out: Op<Endian> = x.clone().into();
                    out
                })
                .collect(),
            tables: item.tables.iter().map(|x| x.clone().into()).collect(),
        };
        out.optimize();
        out
    }
}

impl<Endian: BitOrder + Clone> Pattern<Endian> {
    pub fn append(&mut self, other: &Pattern<Endian>) {
        self.append_and_update_match_numbers(other, None)
    }

    pub fn append_and_update_match_numbers(
        &mut self,
        other: &Pattern<Endian>,
        new_match_number: Option<usize>,
    ) {
        // TODO: Update saved slots?
        let increment = self.steps.len();
        let increment_tables = self.tables.len();
        for inst in &other.steps {
            self.steps.push(inst.get_incremented(
                increment.try_into().unwrap(),
                new_match_number,
                increment_tables,
                0,
            ));
        }
        self.tables.append(&mut other.tables.clone());
    }

    pub fn prepend(&mut self, other: &Pattern<Endian>) {
        // TODO: Update saved slots?
        let increment = other.steps.len();
        let increment_tables = other.tables.len();
        let mut tmp = Vec::with_capacity(increment + self.steps.len());
        for inst in &self.steps {
            tmp.push(inst.get_incremented(
                increment.try_into().unwrap(),
                None,
                increment_tables,
                0,
            ));
        }

        self.steps.clone_from(&other.steps);
        self.steps.append(&mut tmp);

        let mut tmp_tables = self.tables.clone();
        self.tables.clone_from(&other.tables);
        self.tables.append(&mut tmp_tables);
    }

    pub fn insert(&mut self, index: usize, other: &Pattern<Endian>) {
        let insert_length = other.steps.len();

        // Add new steps
        for (i, new_step) in other.steps.iter().enumerate() {
            self.steps.insert(
                index + i,
                new_step.get_incremented(index.try_into().unwrap(), None, self.tables.len(), 0),
            );
        }

        // Increment indexes of steps before and after our inserted range
        let steps_before_range = 0..index;
        let steps_after_range = (index + insert_length)..self.steps.len();
        for i in steps_before_range.chain(steps_after_range) {
            self.steps[i] =
                self.steps[i].get_incremented(insert_length.try_into().unwrap(), None, 0, index);
        }

        // Append the new tables
        self.tables.append(&mut other.tables.clone())
    }

    pub fn remove(&mut self, index: usize, len: usize) {
        // Remove the steps
        self.steps.drain(index..(index + len));

        // Update references in steps
        let decrement_amount: isize = len.try_into().unwrap();
        for i in 0..self.steps.len() {
            self.steps[i] = self.steps[i].get_incremented(-decrement_amount, None, 0, index);
        }

        // remove now-unused tables
        let used_tables = self.get_used_tables();
        for table_index in 0..self.tables.len() {
            // This could all be done more effeciently... but... it probably doesn't matter
            if used_tables.contains(&table_index) {
                continue;
            }
            self.remove_table(table_index);
        }
    }

    pub fn get_used_tables(&self) -> Vec<usize> {
        let mut out = Vec::with_capacity(self.tables.len());
        for step in &self.steps {
            step.get_used_tables(&mut out)
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    pub fn remove_table(&mut self, index: usize) {
        self.tables.remove(index);
        for i in 0..self.steps.len() {
            self.steps[i].decrement_tables_greater_than(index);
        }
    }

    pub fn get_dot_star() -> Self {
        Self {
            steps: vec![
                Op::Split { dest1: 3, dest2: 1 },
                Op::AnyByte,
                Op::Jmp { dest: 0 },
            ],
            tables: vec![],
        }
    }

    pub fn get_save(slot: usize) -> Self {
        Self {
            steps: vec![Op::Save { slot }],
            tables: vec![],
        }
    }

    pub fn get_save_start() -> Self {
        Self {
            steps: vec![Op::SaveStart],
            tables: vec![],
        }
    }

    pub fn combine(&mut self, other: &Pattern<Endian>) {
        // We currently only support combining patterns which both end in a match
        let orig_match_number = if let Some(Op::Match { match_number }) = self.steps.last() {
            *match_number
        } else {
            panic!("Last step of pattern to be combined must be a match!")
        };
        if let Some(Op::Match { match_number: _ }) = other.steps.last() {
            // pass
        } else {
            panic!("Last step of pattern to be combined must be a match!")
        }

        let orig_steps_len = self.steps.len();
        // Add a split at the start:
        self.prepend(&Self {
            steps: vec![Op::Split { dest1: 1, dest2: 2 }],
            tables: vec![],
        });
        // Update the second split dest to point at our second pattern
        if let Some(first_step) = self.steps.get_mut(0) {
            match first_step {
                Op::Split { dest1: _, dest2 } => *dest2 = orig_steps_len + 1,
                _ => panic!("First step should always be a split at this point"),
            }
        }

        self.append_and_update_match_numbers(other, Some(orig_match_number + 1));
    }

    pub fn combine_multiple(&mut self, others: &[Pattern<Endian>]) {
        for other in others {
            self.combine(other);
        }
    }

    /// Determine if there are places where we can add an
    /// [Op::ByteMultiNonconsuming] instructions to speed up processing and add
    /// insert them if we can
    pub fn optimize(&mut self) {
        // Bail if we don't have any splits (optimizing is not going to help)
        if !self.steps.iter().any(|x| {
            matches!(
                x,
                Op::Split { dest1: _, dest2: _ } | Op::SplitMulti { dests: _ }
            )
        }) {
            return;
        }

        // Start from the first instruction and look for all the possible places
        // to optimize
        let mut visited = vec![];
        let mut optimization_points = Some(vec![]);
        self.get_optimize_places_recursive(0, &mut visited, &mut optimization_points);

        // eprintln!("visited {:#?}", visited);
        // eprintln!("optimization_points {:#?}", optimization_points);

        // Get the "weight" of all steps (measures of how early in the tree a
        // step is, and how many immediate children it has)
        let mut weights = HashMap::new();
        self.get_weights(0, &mut vec![], &mut weights);
        // eprintln!("weights {:#?}", weights);

        // Filter our weights to only include steps that can be optimized and
        // which have sufficient weight to make optimizaion worth it
        let mut filtered_weights: Vec<(usize, Weight)> = weights
            .iter()
            .filter(|(idx, w)| {
                optimization_points.as_ref().unwrap().contains(*idx)
                    && w.descendants_weight >= 10
                    && w.children_weight >= 4
            })
            .map(|(x, y)| (*x, *y))
            .collect();
        // Sort from highest step number to lowest step number so that as we
        // insert steps we're not moving where we want to insert
        filtered_weights.sort_by(|a, b| b.0.cmp(&a.0));

        // eprintln!("filtered_weights {:#?}", filtered_weights);

        // Loop over all the good places to optimize and insert the optimization
        for (optimization_idx, _) in filtered_weights {
            // Get the details for this optimization:
            let required_bytes =
                self.get_optimize_places_recursive(optimization_idx, &mut vec![], &mut None);
            if let Some(mut required_bytes_inner) = required_bytes {
                // These steps makes it *slightly* faster for us to run our
                // ByteMultiNonconsuming
                required_bytes_inner.sort_unstable();
                required_bytes_inner.dedup();

                // Add the new step
                self.insert(
                    optimization_idx,
                    &Self {
                        tables: vec![],
                        steps: vec![Op::ByteMultiNonconsuming {
                            value: required_bytes_inner,
                        }],
                    },
                );
                // The insert would have moved any braches coming into the
                // original step to point one lower (where the original step now
                // is). We want to update branches that came into the old
                // instruction to point back at this new optimizing instruction
                self.update_branches(optimization_idx + 1, optimization_idx);
            }
        }
    }

    /// Updates all branches (not fall-through) with a destination of `old` to
    /// instead point to `new`.
    pub fn update_branches(&mut self, old: usize, new: usize) {
        for step in &mut self.steps {
            step.update_branches(old, new)
        }
    }

    /// Checks if "step" is a valid place to add a [Op::ByteMultiNonconsuming]
    /// and if so returns a vector of the bytes to populate in this new
    /// instruction at this step.
    ///
    /// This function calls itself recursively (to handle multiple splits and
    /// non-consuming opcodes)
    ///
    /// # Arguments
    /// * `step` - The step to check if it's a valid possible optimization
    ///   location.
    /// * `visited` - List of steps which have been evaluated so far. Should be
    ///   an empty vec on initial call. If we encounter the same step more than
    ///   once we stop (we've hit a loop)
    /// * `optimization_points` - List of steps where it would be valid to add a
    ///   [Op::ByteMultiNonconsuming]. Should be an empty vec on initial call.
    ///   Should be None if you don't want to re-traverse the whole tree looking
    ///   for places to optimize (e.g.: you only want to find the values for a
    ///   specific step) TODO: We don't really need this None option if we just
    ///   collected and returned all the values for each step as we went through
    ///   the first time. This would probably be *slightly* faster... but.. we
    ///   don't do this often so probably doesn't matter
    ///
    pub fn get_optimize_places_recursive(
        &self,
        step: usize,
        visited: &mut Vec<usize>,
        optimization_points: &mut Option<Vec<usize>>,
    ) -> Option<Vec<u8>> {
        // Keep track of where we've visited
        if visited.contains(&step) {
            return Some(vec![]);
        }
        visited.push(step);

        // Keep a list of children of this step which are themselves optimizable.
        // We'll later possibly remove these from being considered optimization
        // points (because it's better to optimize the parent rather than the
        // children)
        let mut optimizable_children = vec![];

        if step >= self.steps.len() {
            return None;
        }

        // Get the list of bytes (or none) for this step, possibly going
        // recursive depending on the [Op] type.
        let (out, next) = match &self.steps[step] {
            Op::Byte { value } => (Some(vec![*value]), true),
            Op::MaskedByte { mask: _, value: _ } => (None, true),
            Op::ByteMultiNonconsuming { value } => (Some(value.clone()), true),
            Op::Match { match_number: _ } => (None, false),
            Op::Jmp { dest } => {
                let child = self.get_optimize_places_recursive(*dest, visited, optimization_points);
                optimizable_children.push(*dest);
                (child, false)
            }
            Op::Split { dest1, dest2 } => {
                let mut split_out = vec![];
                let mut cant_optimize = false;

                for dest in [*dest1, *dest2] {
                    if let Some(mut a) =
                        self.get_optimize_places_recursive(dest, visited, optimization_points)
                    {
                        split_out.append(&mut a);
                    } else {
                        cant_optimize = true;
                    }
                }
                if cant_optimize {
                    (None, false)
                } else {
                    optimizable_children.push(*dest1);
                    optimizable_children.push(*dest2);

                    (Some(split_out), false)
                }
            }
            Op::SplitMulti { dests } => {
                let mut had_none = false;
                let mut split_out = vec![];
                for dest in dests {
                    if let Some(a) =
                        self.get_optimize_places_recursive(*dest, visited, optimization_points)
                    {
                        split_out.append(&mut a.clone());
                    } else {
                        had_none = true;
                    }
                }
                if had_none {
                    (None, false)
                } else {
                    optimizable_children.append(&mut dests.clone());
                    (Some(split_out), false)
                }
            }
            Op::SaveStart | Op::Save { slot: _ } | Op::Label { value: _ } => {
                let child =
                    self.get_optimize_places_recursive(step + 1, visited, optimization_points);
                optimizable_children.push(step + 1);

                (child, false)
            }
            Op::AnyByte => (None, true),
            Op::AnyByteSequence {
                min: _,
                max: _,
                interval: _,
            } => (None, true),
            Op::Lookup { data: _ } => (None, true),
            Op::LookupQuick { bytes, data: _ } => (Some(bytes.clone()), false),
            Op::NegativeLookahead { pattern: _ } => (None, true),
        };
        if next {
            // just do next so we populate the rest of optimization_points
            let child = self.get_optimize_places_recursive(step + 1, visited, optimization_points);
            if child.is_some() {
                optimizable_children.push(step + 1);
            }
        }

        if out.is_some() {
            if let Some(ref mut x) = optimization_points {
                // If the current step is optimizable, then remove the children of
                // this node which were also found to be optimizable (optimizing
                // this step instead is always going to be better than optimizing
                // one of our children)
                for dest in optimizable_children {
                    x.retain(|x| *x != dest);
                }
                x.push(step);
            }
        }

        out
    }

    /// Gets how "weighty" each step is. See comments on [Weight] for details.
    /// Loops are not currently considered (though they may be in the future)
    ///
    /// # Arguments
    /// * `step` - The step to start getting weights for (all steps reachable
    ///   from this step are also computed)
    /// * `visited` - Initially an empty vector. Keeps track of which steps
    ///   we've visited (so we don't repeat / get stuck in a loop)
    /// * `weights` - Maps step numbers to weights. (initially should be an
    ///   empty HahMap)
    pub fn get_weights(
        &self,
        step: usize,
        visited: &mut Vec<usize>,
        weights: &mut HashMap<usize, Weight>,
    ) -> Weight {
        if visited.contains(&step) {
            return Weight {
                self_weight: 0,
                children_weight: 0,
                descendants_weight: 0,
            };
        }
        visited.push(step);

        enum FallthroughBehavior {
            /// Doesn't fall through
            None,
            /// Falls through and adds to parent's weight
            Adding,
            /// Falls through, but parent matches (so doesn't impact weight)
            Blocking,
        }

        if step >= self.steps.len() {
            return Weight::new(2);
        }

        let (mut weight, next) = match &self.steps[step] {
            Op::Byte { value: _ } => (Weight::new(1), FallthroughBehavior::Blocking),
            Op::MaskedByte { mask: _, value: _ } => (Weight::new(2), FallthroughBehavior::Blocking),
            Op::ByteMultiNonconsuming { value: _ } => {
                (Weight::new(2), FallthroughBehavior::Blocking)
            }
            Op::Match { match_number: _ } => (Weight::new(1), FallthroughBehavior::None),
            Op::Jmp { dest } => {
                let mut w = Weight::new(1);
                w.add_fallthrough_child(self.get_weights(*dest, visited, weights));
                (w, FallthroughBehavior::None)
            }
            Op::Split { dest1, dest2 } => {
                let mut w = Weight::new(3);
                w.add_fallthrough_child(self.get_weights(*dest1, visited, weights));
                w.add_fallthrough_child(self.get_weights(*dest2, visited, weights));
                (w, FallthroughBehavior::None)
            }
            Op::SplitMulti { dests } => {
                let mut out_local = Weight::new(3);
                for dest in dests {
                    out_local.add_fallthrough_child(self.get_weights(*dest, visited, weights));
                }
                (out_local, FallthroughBehavior::None)
            }
            Op::SaveStart | Op::Save { slot: _ } | Op::Label { value: _ } => {
                (Weight::new(1), FallthroughBehavior::Adding)
            }

            Op::AnyByte => (Weight::new(1), FallthroughBehavior::Blocking),
            Op::AnyByteSequence {
                min: _,
                max: _,
                interval: _,
            } => (Weight::new(1), FallthroughBehavior::Blocking),
            Op::Lookup { data: _ } => (Weight::new(6), FallthroughBehavior::Blocking),
            Op::LookupQuick { bytes: _, data: _ } => {
                (Weight::new(1), FallthroughBehavior::Blocking)
            }
            Op::NegativeLookahead { pattern: _ } => (Weight::new(4), FallthroughBehavior::Adding),
        };

        match next {
            FallthroughBehavior::None => (),
            FallthroughBehavior::Adding => {
                weight.add_fallthrough_child(self.get_weights(step + 1, visited, weights));
            }
            FallthroughBehavior::Blocking => {
                weight.add_blocked_child(self.get_weights(step + 1, visited, weights));
            }
        }
        weights.insert(step, weight);
        weight
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Weight {
    /// The "cost" of this step itself
    self_weight: usize,
    /// The "cost" of all the steps reachable in a non-blocking way by falling
    /// through this step (For example: a "byte" instruction blocks because we
    /// can't just fall through it, but splits, jumps, saves all "fall through"
    /// to their next steps)
    ///
    /// This helps us figure out how useful it is to optimize this step (steps
    /// with a large weight here have many immediate children and are thus a
    /// good choice for optimizing. A low weight here indicates the next step
    /// itself is blocking so we're not really adding much adding an
    /// optimization here)
    children_weight: usize,
    /// The "cost" of all children and all their children regardless of blocking
    ///
    /// We can use this to favor optimizations which are earlier in the tree
    /// (e.g. more likely to be hit frequently)
    descendants_weight: usize,
}

impl Weight {
    pub fn new(self_weight: usize) -> Self {
        Self {
            self_weight,
            children_weight: 0,
            descendants_weight: 0,
        }
    }
    pub fn add_fallthrough_child(&mut self, child: Weight) -> &mut Self {
        self.children_weight += child.self_weight + child.children_weight;
        self.descendants_weight += child.self_weight + child.descendants_weight;
        self
    }
    pub fn add_blocked_child(&mut self, child: Weight) -> &mut Self {
        self.descendants_weight += child.self_weight + child.descendants_weight;
        self
    }
    pub fn cmp_descendants(&self, other: &Weight) -> Ordering {
        self.descendants_weight.cmp(&other.descendants_weight)
    }
}

#[cfg(test)]
pub mod tests {
    use hashbrown::HashMap;

    use crate::bitstructs::{
        instruction_encoding_aligned::InstructionEncodingAligned,
        instruction_encoding_u32::InstructionEncodingu32, LookupType, OperandType,
    };

    use super::*;

    #[test]
    fn test_append() {
        let mut prog1 = Pattern::<Msb0> {
            steps: vec![
                Op::Jmp { dest: 3 },
                Op::Split { dest1: 5, dest2: 7 },
                Op::Save { slot: 1 },
                Op::Byte { value: 7 },
                Op::Match { match_number: 0 },
            ],
            tables: vec![],
        };

        let prog2 = Pattern::<Msb0> {
            steps: vec![
                Op::Jmp { dest: 3 },
                Op::Split { dest1: 5, dest2: 7 },
                Op::Save { slot: 1 },
                Op::Byte { value: 12 },
                Op::Match { match_number: 0 },
            ],
            tables: vec![],
        };

        let appended = Pattern::<Msb0> {
            steps: vec![
                Op::Jmp { dest: 3 },
                Op::Split { dest1: 5, dest2: 7 },
                Op::Save { slot: 1 },
                Op::Byte { value: 7 },
                Op::Match { match_number: 0 },
                Op::Jmp { dest: 8 },
                Op::Split {
                    dest1: 10,
                    dest2: 12,
                },
                Op::Save { slot: 1 },
                Op::Byte { value: 12 },
                Op::Match { match_number: 0 },
            ],
            tables: vec![],
        };
        prog1.append(&prog2);
        assert_eq!(prog1, appended);
    }

    #[test]
    fn test_prepend() {
        let prog1 = Pattern::<Msb0> {
            steps: vec![
                Op::Jmp { dest: 3 },
                Op::Split { dest1: 5, dest2: 7 },
                Op::Save { slot: 1 },
                Op::Byte { value: 7 },
                Op::Match { match_number: 0 },
            ],
            tables: vec![],
        };

        let mut prog2 = Pattern::<Msb0> {
            steps: vec![
                Op::Jmp { dest: 3 },
                Op::Split { dest1: 5, dest2: 7 },
                Op::Save { slot: 1 },
                Op::Byte { value: 12 },
                Op::Match { match_number: 0 },
            ],
            tables: vec![],
        };

        let appended = Pattern::<Msb0> {
            steps: vec![
                Op::Jmp { dest: 3 },
                Op::Split { dest1: 5, dest2: 7 },
                Op::Save { slot: 1 },
                Op::Byte { value: 7 },
                Op::Match { match_number: 0 },
                Op::Jmp { dest: 8 },
                Op::Split {
                    dest1: 10,
                    dest2: 12,
                },
                Op::Save { slot: 1 },
                Op::Byte { value: 12 },
                Op::Match { match_number: 0 },
            ],
            tables: vec![],
        };
        prog2.prepend(&prog1);
        assert_eq!(prog2, appended);
    }

    #[test]
    fn test_merge_pattern() {
        let mut prog1 = Pattern::<Msb0> {
            steps: vec![
                Op::Save { slot: 0 },
                Op::Byte { value: 0x5 },
                Op::Save { slot: 1 },
                Op::Match { match_number: 0 },
            ],
            tables: vec![],
        };
        let prog2 = Pattern::<Msb0> {
            steps: vec![
                Op::Save { slot: 0 },
                Op::Byte { value: 0x7 },
                Op::Save { slot: 1 },
                Op::Match { match_number: 0 },
            ],
            tables: vec![],
        };
        let prog_combined = Pattern::<Msb0> {
            steps: vec![
                Op::Split { dest1: 1, dest2: 5 },
                Op::Save { slot: 0 },
                Op::Byte { value: 0x5 },
                Op::Save { slot: 1 },
                Op::Match { match_number: 0 },
                Op::Save { slot: 0 },
                Op::Byte { value: 0x7 },
                Op::Save { slot: 1 },
                Op::Match { match_number: 1 },
            ],
            tables: vec![],
        };

        prog1.combine(&prog2);
        assert_eq!(prog1, prog_combined);
    }

    fn get_prog_combined() -> Pattern<Msb0> {
        Pattern::<Msb0> {
            steps: vec![
                Op::Split {
                    dest1: 1,
                    dest2: 10,
                },
                Op::Split { dest1: 2, dest2: 6 },
                Op::Save { slot: 0 },
                Op::Byte { value: 0x5 },
                Op::Save { slot: 1 },
                // #5
                Op::Match { match_number: 6 },
                Op::Save { slot: 0 },
                Op::Byte { value: 0x7 },
                Op::Save { slot: 1 },
                Op::Match { match_number: 7 },
                // #10
                Op::Save { slot: 0 },
                Op::Byte { value: 0x8 },
                Op::Save { slot: 5 },
                Op::Match { match_number: 8 },
            ],
            tables: vec![],
        }
    }

    #[test]
    fn test_merge_patterns() {
        let mut prog1 = Pattern::<Msb0> {
            steps: vec![
                Op::Save { slot: 0 },
                Op::Byte { value: 0x5 },
                Op::Save { slot: 1 },
                Op::Match { match_number: 6 },
            ],
            tables: vec![],
        };
        let others = vec![
            Pattern::<Msb0> {
                steps: vec![
                    Op::Save { slot: 0 },
                    Op::Byte { value: 0x7 },
                    Op::Save { slot: 1 },
                    Op::Match { match_number: 0 },
                ],
                tables: vec![],
            },
            Pattern::<Msb0> {
                steps: vec![
                    Op::Save { slot: 0 },
                    Op::Byte { value: 0x8 },
                    Op::Save { slot: 5 },
                    Op::Match { match_number: 0 },
                ],
                tables: vec![],
            },
        ];

        let prog_combined = get_prog_combined();

        prog1.combine_multiple(&others);
        assert_eq!(prog1, prog_combined);
    }

    fn get_test_progs_with_tables() -> (Pattern<Msb0>, Pattern<Msb0>, Pattern<Msb0>) {
        let mut table1 = HashMap::new();
        table1.insert("A".to_string(), vec![]);
        let prog1 = Pattern::<Msb0> {
            steps: vec![
                Op::Byte { value: 0x7 },
                Op::Lookup {
                    data: vec![LookupType::MaskAndChooseu32 {
                        mask: 0xFF,
                        choices: vec![InstructionEncodingu32 {
                            value: 0x7,
                            operands: vec![OperandType::Field {
                                table_id: 0,
                                mask: BitVec::new(),
                                var_id: "dummy".to_string(),
                            }],
                            context: None,
                        }],
                    }],
                },
                Op::Match { match_number: 0 },
            ],
            tables: vec![OperandValueTable::new(table1.clone())],
        };

        let mut table2 = HashMap::new();
        table2.insert("B".to_string(), vec![]);
        let prog2 = Pattern::<Msb0> {
            steps: vec![
                Op::Byte { value: 0x3 },
                Op::Lookup {
                    data: vec![LookupType::MaskAndChooseu32 {
                        mask: 0xFF00,
                        choices: vec![InstructionEncodingu32 {
                            value: 0x3,
                            operands: vec![OperandType::Field {
                                table_id: 0,
                                mask: BitVec::new(),
                                var_id: "filler".to_string(),
                            }],
                            context: None,
                        }],
                    }],
                },
                Op::Match { match_number: 0 },
            ],
            tables: vec![OperandValueTable::new(table2.clone())],
        };

        let appended = Pattern::<Msb0> {
            steps: vec![
                Op::Byte { value: 0x7 },
                Op::Lookup {
                    data: vec![LookupType::MaskAndChooseu32 {
                        mask: 0xFF,
                        choices: vec![InstructionEncodingu32 {
                            value: 0x7,
                            operands: vec![OperandType::Field {
                                table_id: 0,
                                mask: BitVec::new(),
                                var_id: "dummy".to_string(),
                            }],
                            context: None,
                        }],
                    }],
                },
                Op::Match { match_number: 0 },
                // Below are prog2's steps
                Op::Byte { value: 0x3 },
                Op::Lookup {
                    data: vec![LookupType::MaskAndChooseu32 {
                        mask: 0xFF00,
                        choices: vec![InstructionEncodingu32 {
                            value: 0x3,
                            operands: vec![OperandType::Field {
                                table_id: 1, // Notice this is different than the original prog2
                                mask: BitVec::new(),
                                var_id: "filler".to_string(),
                            }],
                            context: None,
                        }],
                    }],
                },
                Op::Match { match_number: 0 },
            ],
            tables: vec![
                OperandValueTable::new(table1),
                OperandValueTable::new(table2),
            ],
        };
        (prog1, prog2, appended)
    }

    #[test]
    fn test_append_with_tables() {
        let (mut prog1, prog2, appended) = get_test_progs_with_tables();

        prog1.append(&prog2);
        assert_eq!(prog1, appended);
    }

    #[test]
    fn test_insert_remove() {
        let mut prog1 = Pattern::<Msb0> {
            steps: vec![
                Op::Save { slot: 0 },
                Op::SplitMulti { dests: vec![0, 6] },
                Op::Split { dest1: 1, dest2: 4 },
                Op::Split { dest1: 1, dest2: 4 },
            ],
            tables: vec![],
        };
        let prog2 = Pattern::<Msb0> {
            steps: vec![
                Op::SplitMulti { dests: vec![0, 2] },
                Op::Split { dest1: 2, dest2: 0 },
            ],
            tables: vec![],
        };
        let prog_combined = Pattern::<Msb0> {
            steps: vec![
                Op::Save { slot: 0 },
                Op::SplitMulti { dests: vec![0, 8] },
                Op::Split { dest1: 1, dest2: 6 },
                Op::SplitMulti { dests: vec![3, 5] },
                Op::Split { dest1: 5, dest2: 3 },
                Op::Split { dest1: 1, dest2: 6 },
            ],
            tables: vec![],
        };

        let prog1_orig = prog1.clone();
        prog1.insert(3, &prog2);
        assert_eq!(prog1, prog_combined);

        prog1.remove(3, 2);
        assert_eq!(prog1, prog1_orig);
    }

    #[test]
    fn test_insert_remove_tables() {
        let (mut prog1, prog2, appended) = get_test_progs_with_tables();

        let prog1_orig = prog1.clone();
        prog1.insert(3, &prog2);
        assert_eq!(prog1, appended);

        prog1.remove(3, prog2.steps.len());
        assert_eq!(prog1, prog1_orig)
    }

    #[test]
    fn test_get_weights() {
        let prog = get_prog_combined();
        let mut visited = vec![];
        let mut weights = HashMap::new();
        let out = prog.get_weights(0, &mut visited, &mut weights);

        eprintln!("{:#?}", weights);

        // Make sure we visited everything
        for x in 0..prog.steps.len() {
            assert!(visited.contains(&x));
        }

        let mut expected_weights = HashMap::<usize, Weight>::new();

        expected_weights.insert(
            0,
            Weight {
                self_weight: 3,
                children_weight: 9,
                descendants_weight: 15,
            },
        );
        expected_weights.insert(
            1,
            Weight {
                self_weight: 3,
                children_weight: 4,
                descendants_weight: 8,
            },
        );
        expected_weights.insert(
            2,
            Weight {
                self_weight: 1,
                children_weight: 1,
                descendants_weight: 3,
            },
        );
        expected_weights.insert(
            3,
            Weight {
                self_weight: 1,
                children_weight: 0,
                descendants_weight: 2,
            },
        );
        expected_weights.insert(
            4,
            Weight {
                self_weight: 1,
                children_weight: 1,
                descendants_weight: 1,
            },
        );
        expected_weights.insert(
            5,
            Weight {
                self_weight: 1,
                children_weight: 0,
                descendants_weight: 0,
            },
        );
        expected_weights.insert(
            6,
            Weight {
                self_weight: 1,
                children_weight: 1,
                descendants_weight: 3,
            },
        );
        expected_weights.insert(
            7,
            Weight {
                self_weight: 1,
                children_weight: 0,
                descendants_weight: 2,
            },
        );
        expected_weights.insert(
            8,
            Weight {
                self_weight: 1,
                children_weight: 1,
                descendants_weight: 1,
            },
        );
        expected_weights.insert(
            9,
            Weight {
                self_weight: 1,
                children_weight: 0,
                descendants_weight: 0,
            },
        );
        expected_weights.insert(
            10,
            Weight {
                self_weight: 1,
                children_weight: 1,
                descendants_weight: 3,
            },
        );
        expected_weights.insert(
            11,
            Weight {
                self_weight: 1,
                children_weight: 0,
                descendants_weight: 2,
            },
        );
        expected_weights.insert(
            12,
            Weight {
                self_weight: 1,
                children_weight: 1,
                descendants_weight: 1,
            },
        );
        expected_weights.insert(
            13,
            Weight {
                self_weight: 1,
                children_weight: 0,
                descendants_weight: 0,
            },
        );

        eprintln!("{:?}", expected_weights);
        // assert_eq!(expected_weights, weights);
        assert_eq!(
            out,
            Weight {
                self_weight: 3,
                children_weight: 9,
                descendants_weight: 15,
            }
        );
    }

    #[test]
    fn test_optimize() {
        let mut prog1 = Pattern::<Msb0> {
            steps: vec![
                // The order of these splits is important for the test. With
                // them in this order, the naive approach will choose to
                // optimize a branch that only has one option (not great) so we
                // want to make sure the weights push it the other way
                // (optimizig at #6)
                Op::Split { dest1: 6, dest2: 1 },
                Op::Split { dest1: 2, dest2: 4 },
                Op::Byte { value: 0xa },
                Op::Match { match_number: 0 },
                Op::MaskedByte {
                    value: 0xb,
                    mask: 0x7,
                },
                Op::Match { match_number: 1 },
                // #6
                Op::Split {
                    dest1: 7,
                    dest2: 10,
                },
                Op::Split {
                    dest1: 8,
                    dest2: 10,
                },
                Op::Split {
                    dest1: 9,
                    dest2: 10,
                },
                Op::Split {
                    dest1: 8,
                    dest2: 10,
                },
                //#10
                Op::LookupQuick {
                    bytes: vec![0x1],
                    data: vec![LookupType::MaskAndChooseAligned {
                        mask: vec![0xff, 0xff],
                        choices: vec![InstructionEncodingAligned {
                            value: vec![0x01, 0x02],
                            operands: vec![],
                            context: None,
                        }],
                    }],
                },
                Op::Match { match_number: 2 },
            ],
            tables: vec![],
        };

        let prog_expected = Pattern::<Msb0> {
            steps: vec![
                Op::Split { dest1: 6, dest2: 1 },
                Op::Split { dest1: 2, dest2: 4 },
                Op::Byte { value: 0xa },
                Op::Match { match_number: 0 },
                Op::MaskedByte {
                    value: 0xb,
                    mask: 0x7,
                },
                Op::Match { match_number: 1 },
                // #6
                Op::ByteMultiNonconsuming { value: vec![0x1] },
                Op::Split {
                    dest1: 8,
                    dest2: 11,
                },
                Op::Split {
                    dest1: 9,
                    dest2: 11,
                },
                Op::Split {
                    dest1: 10,
                    dest2: 11,
                },
                Op::Split {
                    dest1: 9,
                    dest2: 11,
                },
                //#11
                Op::LookupQuick {
                    bytes: vec![0x1],
                    data: vec![LookupType::MaskAndChooseAligned {
                        mask: vec![0xff, 0xff],
                        choices: vec![InstructionEncodingAligned {
                            value: vec![0x01, 0x02],
                            operands: vec![],
                            context: None,
                        }],
                    }],
                },
                Op::Match { match_number: 2 },
            ],
            tables: vec![],
        };

        prog1.optimize();

        assert_eq!(prog1, prog_expected);
    }
}
