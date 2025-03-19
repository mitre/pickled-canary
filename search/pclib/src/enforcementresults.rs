// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use std::collections::{BTreeMap, BTreeSet};
use treesearchlib::automata::*;

/// Container for either holding a reference (in the form of a map key) to a vec
/// of [Results] or a boolean result
#[derive(Debug, Clone)]
pub enum ConstraintResult {
    Results { key: String },
    Bool { result: bool },
}

#[derive(Debug, Clone)]
pub struct EnforcementResults {
    constraint_results: BTreeMap<String, ConstraintResult>,
    tags: BTreeSet<String>,
}

impl EnforcementResults {
    pub fn add_constraint_result(
        &mut self,
        constraint_name: &str,
        constraint_result: ConstraintResult,
    ) {
        self.constraint_results
            .insert(constraint_name.to_string(), constraint_result);
    }

    pub fn get_constraint_result(&self, constraint_name: &str) -> Option<&ConstraintResult> {
        self.constraint_results.get(constraint_name)
    }

    pub fn get_all_constraint_results(&self) -> &BTreeMap<String, ConstraintResult> {
        &self.constraint_results
    }

    pub fn add_tags(&mut self, new_tags: &[String]) {
        for new_tag in new_tags {
            self.tags.insert(new_tag.to_owned());
        }
    }

    pub fn get_tags(&self) -> &BTreeSet<String> {
        &self.tags
    }
}

impl From<&BTreeMap<String, Vec<Results>>> for EnforcementResults {
    /// Given a map of pattern names and their corrisponding results, transform
    /// these into a map of pattern name --> [EnforcementResults]
    fn from(input_items: &BTreeMap<String, Vec<Results>>) -> Self {
        let mut out = Self {
            constraint_results: BTreeMap::new(),
            tags: BTreeSet::new(),
        };
        for key in input_items.keys() {
            out.constraint_results.insert(
                key.to_string(),
                ConstraintResult::Results {
                    key: key.to_string(),
                },
            );
        }
        out
    }
}
