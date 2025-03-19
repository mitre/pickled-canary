// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use crate::automata::thread::SavedData;

#[derive(Debug, PartialEq, Eq)]
pub struct Results {
    pub matched: bool,
    pub match_number: Option<usize>,
    pub saved: Option<SavedData>,
}
