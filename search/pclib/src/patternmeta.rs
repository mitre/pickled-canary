// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

use bitvec::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use treesearchlib::automata::*;
use treesearchlib::b::{AddressedBits, Pattern as BitPattern};
use treesearchlib::bitstructs::Op;

use crate::core;
use crate::enforcementerror::{EnforcementError, EnforcementErrorType};
use crate::enforcementresults::{ConstraintResult, EnforcementResults};

/// Used for storing multiple patterns and the relationships between them.
///
/// You probably want to create a JSON file conforming to PatternMetaJson and
/// then pass a path to this file to
/// [PatternMeta::load_pattern_meta]
#[derive(Debug, Clone)]
pub struct PatternMeta<Endian: BitOrder + Clone + PartialEq> {
    pub patterns: Vec<BitPattern<Endian>>,
    pub pattern_names: Vec<String>,
    pub constraints: Vec<Constraint>,
    pub path: PathBuf,
    pub combined_pattern: Option<BitPattern<Endian>>,
}

impl<Endian: BitOrder + Clone + std::fmt::Debug + PartialEq> From<PatternMetaJson>
    for PatternMeta<Endian>
{
    fn from(item: PatternMetaJson) -> Self {
        let mut patterns = Vec::with_capacity(item.patterns.len());
        let mut pattern_names = Vec::with_capacity(item.patterns.len());

        for x in item.patterns {
            let k = x.name;
            let v = x.file;
            let mut pattern = core::load_pattern_raw::<Endian>(Some(&item.path), &v, 1);
            pattern.append(&BitPattern::get_save(1));
            pattern.steps.push(Op::Match { match_number: 0 });
            patterns.push(pattern);
            pattern_names.push(k);
        }
        let mut out = Self {
            patterns,
            pattern_names,
            constraints: item.constraints,
            path: item.path,
            combined_pattern: None,
        };
        out.combine_patterns();
        out
    }
}

impl<Endian: BitOrder + Clone + std::fmt::Debug + PartialEq> PatternMeta<Endian> {
    /// Given a path to a file, return a fully populated PatternMeta
    pub fn load_pattern_meta(pattern_meta_file_path: &str) -> PatternMeta<Endian> {
        let pattern_data = fs::read(pattern_meta_file_path).unwrap();
        let mut pattern: PatternMetaJson = serde_json::from_slice(&pattern_data).unwrap();
        pattern.path = PathBuf::from(pattern_meta_file_path);
        pattern.path.pop();
        pattern.into()
    }

    /// Merge each of the patterns in this object into a single pattern,
    /// optimize it and populate that pattern into the combined_pattern field.
    pub fn combine_patterns(&mut self) {
        let mut mega_pattern = BitPattern::get_dot_star();
        mega_pattern.append(&BitPattern::get_save_start());
        let mut combined_patterns = self.patterns.get(0).unwrap().clone();
        combined_patterns.combine_multiple(&self.patterns[1..]);
        mega_pattern.append(&combined_patterns);

        mega_pattern.optimize();
        self.combined_pattern = Some(mega_pattern);
    }

    fn format_results(&self, results: Vec<Results>) -> BTreeMap<String, Vec<Results>> {
        // Create our output map and populate it with empty vectors
        let mut ptn_results: BTreeMap<String, Vec<Results>> = BTreeMap::new();
        for pattern_name in &self.pattern_names {
            ptn_results.insert(pattern_name.to_string(), vec![]);
        }

        // Populate the (match) results into the vector we just created.
        for result in results {
            if let Some(match_number) = result.match_number {
                // Notice, this also populates ptn_results because this variable
                // is just references into that one
                let match_name = self.pattern_names.get(match_number).expect(
                    "Got a match_number larger than the number of patterns supplied to the meta",
                );
                ptn_results.get_mut(match_name).unwrap().push(result);
            }
        }

        ptn_results
    }

    /// Execute all the patterns found in this PatternMeta on the given file
    ///
    /// Returns a map of pattern names to vec of [Results] (one per match for "pattern name")
    fn run_patterns(
        &self,
        short_circuit: bool,
        data_file_path: &str,
        use_memory_map: bool,
    ) -> BTreeMap<String, Vec<Results>> {
        let results = core::run_pattern(
            short_circuit,
            data_file_path,
            self.combined_pattern.as_ref().expect("Meta pattern must have combined_pattern by this point. How did you get here with it not yet combined?"),
            1,
            use_memory_map,
        );
        self.format_results(results)
    }

    #[allow(dead_code)]
    pub fn run_patterns_data(
        &self,
        short_circuit: bool,
        data_vec: &[u8],
    ) -> BTreeMap<String, Vec<Results>> {
        let mega_pattern = self.combined_pattern.as_ref().expect("Meta pattern must have combined_pattern by this point. How did you get here with it not yet combined?");
        // eprintln!("{:#?}", mega_pattern);
        let results = core::run_pattern_data(short_circuit, data_vec, mega_pattern, 1);
        self.format_results(results)
    }
    #[allow(dead_code)]
    pub fn run_patterns_data_automata(
        &self,
        short_circuit: bool,
        data_vec: &[u8],
        automata: fn(usize, &BitPattern<Endian>, &AddressedBits) -> Results,
    ) -> BTreeMap<String, Vec<Results>> {
        let mega_pattern = self.combined_pattern.as_ref().expect("Meta pattern must have combined_pattern by this point. How did you get here with it not yet combined?");
        // eprintln!("{:#?}", mega_pattern);
        let results =
            core::run_pattern_data_automata(short_circuit, data_vec, mega_pattern, 1, automata);
        self.format_results(results)
    }

    /// Given a set of pattern results (for a single input file), enforce the
    /// constraints in this PatternMeta upon the results and see if they hold.
    ///
    /// Takes as input a map of pattern names to vec of individual match
    /// [Results]
    fn enforce(
        &self,
        results: &BTreeMap<String, Vec<Results>>,
        enforcement_results: &mut EnforcementResults,
    ) -> Result<(), EnforcementError> {
        // Loop over all constraints (in order because it's a BTreeMap)
        for (constraint_number, constraint) in self.constraints.iter().enumerate() {
            let (constraint_result, enforcement_error) = match &constraint.constraint_type {
                ConstraintType::SingleHit { input } => {
                    let source = results.get(input).unwrap();
                    let got_one_hit = source.iter().filter(|x| x.matched).count() == 1;

                    (
                        ConstraintResult::Bool {
                            result: got_one_hit,
                        },
                        if !got_one_hit {
                            Some(EnforcementErrorType::MultipleHits)
                        } else {
                            None
                        },
                    )
                }
                ConstraintType::Xor { inputs } => {
                    let result = inputs
                        // Loop over all our inputs
                        .iter()
                        // Convert them to a boolean (true == 1 hit or previous
                        // constraint was true)
                        .map(|input| match enforcement_results.get_constraint_result(input).unwrap() {
                            // If input corrisponds to a "Results" type, make
                            // sure that pattern only had one hit
                            ConstraintResult::Results { key } => {
                                results
                                    .get(key)
                                    .unwrap()
                                    .iter()
                                    .map(|x| usize::from(x.matched))
                                    .sum::<usize>()
                                    == 1
                            }
                            // If input is a bool result of a previous
                            // constraint, just use that value
                            ConstraintResult::Bool { result } => *result,
                        })
                        // Change our booleans to 1's and zeros
                        .map(usize::from)
                        // Sum up how many "true" values we had
                        .sum::<usize>()
                        // We only want to declare success if there was only a
                        // single true value among our inputs, so check that
                        == 1;

                    (
                        ConstraintResult::Bool { result },
                        if !result {
                            Some(EnforcementErrorType::XorFailure)
                        } else {
                            None
                        },
                    )
                }
                ConstraintType::AtLeastOneHit { input } => {
                    let source = results.get(input).unwrap();
                    let got_one_or_more_hit = source.iter().filter(|x| x.matched).count() >= 1;

                    (
                        ConstraintResult::Bool {
                            result: got_one_or_more_hit,
                        },
                        if !got_one_or_more_hit {
                            Some(EnforcementErrorType::MultipleHits)
                        } else {
                            None
                        },
                    )
                }
                ConstraintType::NoHits { input } => {
                    let source = results.get(input).unwrap();
                    let got_no_hits = source.iter().filter(|x| x.matched).count() == 0;

                    (
                        ConstraintResult::Bool {
                            result: got_no_hits,
                        },
                        if !got_no_hits {
                            Some(EnforcementErrorType::MultipleHits)
                        } else {
                            None
                        },
                    )
                }
                ConstraintType::Not { input } => {
                    let source = enforcement_results.get_constraint_result(input).unwrap();
                    let inverse_value = match source {
                        ConstraintResult::Results { key: _ } => todo!(),
                        ConstraintResult::Bool { result } => !result,
                    };

                    (
                        ConstraintResult::Bool {
                            result: inverse_value,
                        },
                        if !inverse_value {
                            Some(EnforcementErrorType::MultipleHits)
                        } else {
                            None
                        },
                    )
                }
            };

            // Add tags if appropriate
            if let ConstraintResult::Bool { result } = constraint_result {
                if let Some(x) = &constraint.true_tags {
                    if result {
                        enforcement_results.add_tags(x);
                    }
                }
                if let Some(x) = &constraint.false_tags {
                    if !result {
                        enforcement_results.add_tags(x);
                    }
                }
            }

            // Record our result
            enforcement_results.add_constraint_result(&constraint.name, constraint_result);

            if let Some(enforcement_error_inner) = enforcement_error {
                if constraint.is_error {
                    return Err(EnforcementError {
                        constraint_number,
                        error_type: enforcement_error_inner,
                    });
                }
            }
        }
        Ok(())
    }

    pub fn run_enforce_and_reduce<'a>(
        &self,
        short_circuit: bool,
        data_file_path: &'a str,
        use_memory_map: bool,
    ) -> (&'a str, bool, BTreeMap<String, usize>, EnforcementResults) {
        let results = self.run_patterns(short_circuit, data_file_path, use_memory_map);

        let mut enforcement_results = EnforcementResults::from(&results);

        let did_enforce = self.enforce(&results, &mut enforcement_results);

        (
            data_file_path,
            did_enforce.is_ok(),
            results
                .iter()
                .map(|(k, v)| (k.to_string(), v.len()))
                .collect(),
            enforcement_results,
        )
    }
}

/// Metadata about a set of patterns. For instance, can be setup so multiple
/// patterns are run, only one of which should hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PatternMetaJson {
    /// List of patterns to be searched.
    ///
    /// Patterns are combined IN ORDER. The first pattern to complete for a
    /// particular offest in the file is the only pattern which will record a
    /// hit for that offset.
    patterns: Vec<NamedPattern>,
    /// List of constraints to enforce upon sets of pattern matches
    constraints: Vec<Constraint>,

    /// Path to this file (filled in automatically by the code. Ignored if found
    /// in JSON)
    #[serde(skip)]
    path: PathBuf,
}

/// Map of pattern names to pattern filepaths. Paths are relative to the
/// location of this file
///
/// NOTE: These should be paths to the COMPILED patterns!
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedPattern {
    /// The name of this pattern
    pub name: String,
    /// Path to the compiled pattern, relative to the location of this JSON file
    pub file: String,
}

/// Constraints to enforce upon a set of pattern results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    /// The name we'll seave this result using (can be referenced in other
    /// constraints)
    pub name: String,

    /// If this is true, a failure of this constraint is fatal
    is_error: bool,

    /// Tags for this binary if this constraint is true
    pub true_tags: Option<Vec<String>>,

    /// Tags for this binary if this constraint is true
    pub false_tags: Option<Vec<String>>,

    constraint_type: ConstraintType,
}

/// Constraints to enforce upon a set of pattern results
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ConstraintType {
    /// Only one of the names found in "inputs" should be true.
    Xor {
        /// List of names of other constraints, one of which must have a single
        /// hit
        inputs: Vec<String>,
    },

    /// Records "true" for "name" if there's exactly one hit for the "input"
    SingleHit {
        /// Name of pattern which must have exactly 1 hit for this to save
        /// "true"
        input: String,
    },

    /// Records "true" for "name" if there's at least one hit for the "input"
    AtLeastOneHit {
        /// Name of pattern which must have exactly 1 hit for this to save
        /// "true"
        input: String,
    },

    /// Records "true" for "name" if there are no hits for the "input"
    NoHits {
        /// Name of pattern which must have exactly 1 hit for this to save
        /// "true"
        input: String,
    },

    /// Records "true" for "name" if the "input" is false (and vice versa)
    Not {
        /// Name of pattern which must have exactly 1 hit for this to save
        /// "true"
        input: String,
    },
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_meta() {
        let mut meta1 = PatternMeta::<Msb0> {
            patterns: vec![
                BitPattern {
                    steps: vec![Op::Byte { value: 0x1 }, Op::Match { match_number: 0 }],
                    tables: vec![],
                },
                BitPattern {
                    steps: vec![Op::Byte { value: 0x2 }, Op::Match { match_number: 0 }],
                    tables: vec![],
                },
                BitPattern {
                    steps: vec![Op::Byte { value: 0x3 }, Op::Match { match_number: 0 }],
                    tables: vec![],
                },
            ],
            pattern_names: vec!["one".to_string(), "two".to_string(), "three".to_string()],
            constraints: vec![
                Constraint {
                    name: "one1".to_string(),
                    is_error: false,
                    constraint_type: ConstraintType::AtLeastOneHit {
                        input: "one".to_string(),
                    },
                    true_tags: None,
                    false_tags: None,
                },
                Constraint {
                    name: "two1".to_string(),
                    is_error: false,
                    constraint_type: ConstraintType::AtLeastOneHit {
                        input: "one".to_string(),
                    },
                    true_tags: None,
                    false_tags: None,
                },
                Constraint {
                    name: "three1".to_string(),
                    is_error: false,
                    constraint_type: ConstraintType::AtLeastOneHit {
                        input: "one".to_string(),
                    },
                    true_tags: None,
                    false_tags: None,
                },
                Constraint {
                    name: "dummy".to_string(),
                    is_error: true,
                    constraint_type: ConstraintType::Xor {
                        inputs: vec!["one1".to_string(), "two1".to_string(), "three1".to_string()],
                    },
                    true_tags: None,
                    false_tags: None,
                },
            ],
            path: "./".to_string().into(),
            combined_pattern: None,
        };
        meta1.combine_patterns();

        assert!(meta1.combined_pattern.is_some());

        let results = meta1.run_patterns_data(false, &[1, 2, 3]);
        eprintln!("{:?}", results);

        let one = results.get("one").unwrap();
        assert_eq!(one.len(), 1);
        assert!(one.get(0).unwrap().matched);
        let one = results.get("two").unwrap();
        assert_eq!(one.len(), 1);
        assert!(one.get(0).unwrap().matched);
        let one = results.get("three").unwrap();
        assert_eq!(one.len(), 1);
        assert!(one.get(0).unwrap().matched);
    }
}
