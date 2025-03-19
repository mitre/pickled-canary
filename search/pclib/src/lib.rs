#![feature(test)]
/// This library provides exported functions which are intended to be called by
/// non-rust programs/libraries. See the pclib python library for an example.
///
/// This is a work-in-progress
///
/// Pages that helped with this:
///  * https://depth-first.com/articles/2020/08/03/wrapping-rust-types-as-python-classes/
///  * http://saidvandeklundert.net/learn/2021-11-06-calling-rust-from-python/
///  * https://doc.rust-lang.org/nomicon/ffi.html *
///
// Copyright (C) 2025 The MITRE Corporation All Rights Reserved
pub mod core;
pub mod enforcementerror;
pub mod enforcementresults;
pub mod patternmeta;
mod results_iterator;
pub mod saved_data_reader;
use ::core::slice;
use bitvec::order::Msb0;
use results_iterator::ResultsIterator;
use saved_data_reader::SavedDataReader;
use std::convert::{TryFrom, TryInto};
use std::ffi::{c_void, CStr};
use std::os::raw::{c_char, c_longlong, c_ulonglong};
use std::panic::catch_unwind;
use treesearchlib::bitstructs::Pattern;

/// Runs the given pattern against the given data (of length len).
///
/// # Safety
/// The given c_string_pattern MUST be a valid c string.
#[no_mangle]
pub unsafe extern "cdecl" fn load_and_run_pattern(
    c_string_pattern: *const c_char,
    c_data: *mut c_char,
    len: c_ulonglong,
) -> *mut ResultsIterator {
    if c_string_pattern.is_null() || c_data.is_null() {
        return std::ptr::null_mut::<c_void>() as *mut ResultsIterator;
    }

    let result = catch_unwind(|| {
        let pattern_string = unsafe { CStr::from_ptr(c_string_pattern).to_str().unwrap() };
        let compiled_pattern = core::wrap_pattern(core::load_pattern_from_data::<Msb0>(
            pattern_string.as_bytes(),
            3,
        ));

        // eprintln!("Compiled Pattern: {:x?}", compiled_pattern);
        let data_vec: &[u8] = unsafe { slice::from_raw_parts(c_data as *mut u8, len as usize) };
        // eprintln!("Data: {:x?}", data_vec);

        core::run_pattern_data(false, data_vec, &compiled_pattern, 3)
    });

    // return zero if we had a panic, else return a ResultsIterator
    match result {
        Ok(results_vec) => Box::into_raw(Box::new(ResultsIterator::new(0, results_vec))),
        Err(_) => std::ptr::null_mut::<c_void>() as *mut ResultsIterator,
    }
}

/// Returns the offset into the search binary of the next match in the given
/// [ResultsIterator]. Returns -1 if there are no more matches.
///
/// # Safety
/// The given c_results MUST be a valid results pointer which was returned by
/// [load_and_run_pattern].
#[no_mangle]
pub unsafe extern "cdecl" fn iterate_results(c_results: *mut ResultsIterator) -> c_longlong {
    if c_results.is_null() {
        return -1;
    }

    let ri: &mut ResultsIterator = unsafe { &mut *c_results };

    match ri.get_next_offset_from_results() {
        Some(x) => i64::from(x),
        None => -1,
    }
}

/// Returns the next match in the given [ResultsIterator]. Returns -1 if there
/// are no more matches.
///
/// # Safety
/// The given c_results MUST be a valid results pointer which was returned by
/// [load_and_run_pattern].
#[no_mangle]
pub unsafe extern "cdecl" fn iterate_results_full(
    c_results: *mut ResultsIterator,
) -> *mut SavedDataReader {
    if !c_results.is_null() {
        let ri: &mut ResultsIterator = unsafe { &mut *c_results };

        if let Some(x) = ri.get_next_result_from_results() {
            return x;
        }
    }
    Box::into_raw(Box::new(SavedDataReader::err()))
}

/// Frees the given [SavedDataReader]
///
/// # Safety
/// Pointer passed to this function must be a valid pointer to a
/// Box<[SavedDataReader]> (i.e.: What is returned from [iterate_results_full])
#[no_mangle]
pub unsafe extern "cdecl" fn free_saved_data_reader(c_results: *mut SavedDataReader) {
    if c_results.is_null() || c_results == usize::MAX as *mut SavedDataReader {
        return;
    }
    drop(Box::from_raw(c_results));
}

/// Frees the given [ResultsIterator]
///
/// # Safety
/// Pointer passed to this function must be a valid pointer to a
/// Box<[ResultsIterator]> (i.e.: What is returned from [load_and_run_pattern])
#[no_mangle]
pub unsafe extern "cdecl" fn free_results(c_results: *mut ResultsIterator) {
    if c_results.is_null() {
        return;
    }
    drop(Box::from_raw(c_results));
}

/// Creates a [treesearchlib::bitstructs::Pattern]
/// Should be destroyed by calling [free_pattern]
///
/// # Safety
/// The given c_string_pattern MUST be a valid c string
#[no_mangle]
pub unsafe extern "cdecl" fn load_pattern(c_string_pattern: *const c_char) -> *const Pattern<Msb0> {
    if c_string_pattern.is_null() {
        return std::ptr::null_mut::<c_void>() as *const Pattern<Msb0>;
    }

    let pattern = catch_unwind(|| {
        let pattern_string = unsafe { CStr::from_ptr(c_string_pattern).to_str().unwrap() };
        let compiled_pattern = core::wrap_pattern(core::load_pattern_from_data::<Msb0>(
            pattern_string.as_bytes(),
            3,
        ));
        compiled_pattern
    });

    match pattern {
        Ok(p) => {
            let ret_pattern = Box::new(p);
            Box::into_raw(ret_pattern)
        }
        Err(_) => std::ptr::null_mut::<c_void>() as *const Pattern<Msb0>,
    }
}

/// Frees the given [treesearchlib::bitstructs::Pattern]
///
/// # Safety
/// Pointer passed to this function must be a valid pointer to a
/// Box<[treesearchlib::bitstructs::Pattern]> (i.e.: What is returned from [load_pattern])
#[no_mangle]
pub unsafe extern "cdecl" fn free_pattern(c_pattern: *mut Pattern<Msb0>) {
    if c_pattern.is_null() {
        return;
    }
    drop(Box::from_raw(c_pattern));
}

// TODO should this return a more rich "Result" struct that includes captures registers?
/// Run a pattern one time over some data from a given offset
///
/// # Safety
/// c_pattern should only be a pattern pointer that was returned from [load_pattern]
/// c_data should be a character pointer
/// len should be the length of the data pointed to by c_data
#[no_mangle]
pub unsafe extern "cdecl" fn run_pattern_once(
    c_pattern: *const Pattern<Msb0>,
    c_data: *mut c_char,
    len: c_ulonglong,
    offset: c_ulonglong,
) -> c_longlong {
    if c_pattern.is_null() || c_data.is_null() || offset >= len {
        return -1;
    }

    let pc_result = catch_unwind(|| {
        let pattern: &Pattern<Msb0> = unsafe { &*c_pattern };
        // eprintln!("Compiled Pattern: {:x?}", compiled_pattern);
        let data_vec: &[u8] = unsafe { slice::from_raw_parts(c_data as *mut u8, len as usize) };
        // eprintln!("Data: {:x?}", data_vec);

        core::run_pattern_data_once(data_vec, pattern, 3, offset.try_into().unwrap())
    });

    match pc_result {
        Ok(result) => {
            if result.matched {
                if let Some(x) = result.saved.as_ref() {
                    let location = x.start.unwrap();
                    return i64::try_from(location).unwrap_or(-1);
                }
            }

            -1
        }

        Err(_) => -1,
    }
}
