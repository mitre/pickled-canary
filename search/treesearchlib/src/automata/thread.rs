// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use core::clone::Clone;
use core::fmt;
use core::fmt::Debug;
use core::hash::Hash;

/// Holds "[saved](crate::bitstructs::Op::Save)" indexes and variable values
/// (from [Lookup](crate::bitstructs::Op::Lookup) steps) as well as where this
/// state started matching (as recorded by
/// [SaveStart](crate::bitstructs::Op::SaveStart)).
#[derive(Clone, Default, Debug, Hash, PartialEq, Eq)]
pub struct SavedData {
    pub start: Option<usize>,
    pub captures: BTreeMap<usize, usize>,
    pub variables: BTreeMap<String, String>,
    pub labels: BTreeMap<String, i128>,
    pub values: BTreeMap<String, i64>,
}

impl SavedData {
    pub fn new() -> Self {
        SavedData {
            start: None,
            captures: BTreeMap::new(),
            variables: BTreeMap::new(),
            labels: BTreeMap::new(),
            values: BTreeMap::new(),
        }
    }
    pub fn eq_ignoring_start(&self, other: &Self) -> bool {
        self.captures == other.captures && self.variables == other.variables
    }
}

/// Keeps track of our current step (pc_index) and its corrisponding [SavedData]
#[derive(Clone, Debug, Hash)]
pub struct Thread {
    pub pc_idx: usize,
    pub saved: SavedData,
}

impl Thread {
    pub fn new(pc_idx: usize, saved: &SavedData) -> Self {
        Self {
            pc_idx,
            saved: saved.clone(),
        }
    }
}

/// Same as [Thread] but more effecient because [SavedData] is only copied when
/// necessary
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct ThreadRc {
    pub pc_idx: usize,
    pub saved: Rc<SavedData>,
    pub start: Option<usize>,
}

impl ThreadRc {
    pub fn new(pc_idx: usize, saved: &Rc<SavedData>, start: Option<usize>) -> Self {
        Self {
            pc_idx,
            saved: Rc::clone(saved),
            start,
        }
    }

    pub fn eq_ignoring_start(&self, other: &Self) -> bool {
        self.pc_idx == other.pc_idx && self.saved.eq_ignoring_start(&other.saved)
    }
}

impl Default for ThreadRc {
    fn default() -> Self {
        Self {
            pc_idx: 0,
            saved: Rc::new(SavedData::new()),
            start: None,
        }
    }
}

impl Debug for ThreadRc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pc={} saved={:?}", self.pc_idx, self.saved)
    }
}
