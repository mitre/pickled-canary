// Copyright (C) 2025 The MITRE Corporation All Rights Reserved
use crate::saved_data_reader::SavedDataReader;
use std::convert::TryFrom;
use treesearchlib::automata::Results;

#[derive(Debug)]
pub struct ResultsIterator {
    cur_idx: usize,
    results: Vec<Results>,
}

/// Get the match start offset from the given result
fn get_offset(result: &Results) -> Option<u32> {
    let current_first_capture = result.saved.as_ref()?.start?;
    // Convert capture from a usize to a u32
    let out: Option<u32> = u32::try_from(current_first_capture).ok();
    out
}

/// Get a [SavedDataReader] structure from the given result
fn get_result(result: &Results) -> Option<*mut SavedDataReader> {
    result
        .saved
        .as_ref()
        .map(|s| Box::into_raw(Box::new(SavedDataReader::new(s))))
}

impl ResultsIterator {
    pub fn new(cur_idx: usize, results: Vec<Results>) -> Self {
        Self { cur_idx, results }
    }

    /// Gets the next value from this iterator
    ///
    /// Uses the provided "getter" function to determine what type of value we're
    /// going to get. Increments the internal index so the next call to this
    /// function will return the next value
    fn get_next<T>(&mut self, getter: fn(&Results) -> Option<T>) -> Option<T> {
        let current_result = self.results.get(self.cur_idx)?;
        if current_result.matched {
            let out = getter(current_result);
            // Make sure we'll move on to the next mach the next time we're called
            self.cur_idx += 1;
            return out;
        }
        // It's weird to have a match after a non-match... but incrementing here
        // will let us reach the later match if such a thing occurs
        self.cur_idx += 1;
        None
    }

    /// Get the next [SavedDataReader] from this iterator or None if there is no
    /// next
    pub fn get_next_result_from_results(&mut self) -> Option<*mut SavedDataReader> {
        self.get_next(get_result)
    }

    /// Get the next match start offset from this iterator or None  
    pub fn get_next_offset_from_results(&mut self) -> Option<u32> {
        self.get_next(get_offset)
    }
}
