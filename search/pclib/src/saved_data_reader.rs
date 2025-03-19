// Copyright (C) 2025 The MITRE Corporation All Rights Reserved
use core::ffi::{c_int, c_ulonglong};
use std::{collections::BTreeMap, convert::TryInto, ffi::CString, mem, ptr};

use treesearchlib::automata::thread::SavedData;

type RawCStrPtr = *mut i8;

/// A structure for passing pattern results to C compatiable FFI
#[repr(C)]
#[derive(Debug)]
pub struct SavedDataReader {
    pub status: c_int,
    pub start: c_ulonglong,
    pub values_len: c_ulonglong,
    pub values_capacity: c_ulonglong,
    pub values: *mut (RawCStrPtr, i64),

    pub labels_len: c_ulonglong,
    pub labels_capacity: c_ulonglong,
    // The slice here is actually a little endian i128
    pub labels: *mut (RawCStrPtr, [u8; 16]),

    pub variables_len: c_ulonglong,
    pub variables_capacity: c_ulonglong,
    pub variables: *mut (RawCStrPtr, RawCStrPtr),
}

fn my_clone<T: Clone>(input: &T) -> T {
    input.clone()
}

fn my_to_le_bytes(input: &i128) -> [u8; 16] {
    input.to_le_bytes()
}

#[allow(clippy::ptr_arg)]
fn my_to_raw_c_str_ptr(input: &String) -> RawCStrPtr {
    CString::new(input.clone())
        .expect("Value shouldn't ever have a null in the middle")
        .into_raw()
}

/// Convert a btree to a vector of tuples (which we can send to a C-FFI program)
///
/// Uses the given transform argument to convert the value of teach btree entry
/// to another type to be used as the second value of each output tuple
fn btree_to_vec<T, U>(input: &BTreeMap<String, T>, transform: fn(&T) -> U) -> Vec<(RawCStrPtr, U)> {
    let mut out: Vec<(RawCStrPtr, U)> = input
        .iter()
        .map(|(k, v)| {
            (
                CString::new(k.clone())
                    .expect("Name shouldn't ever have a null in the middle")
                    .into_raw(),
                transform(v),
            )
        })
        .collect();
    out.shrink_to_fit();
    out
}

impl SavedDataReader {
    pub fn err() -> Self {
        Self {
            status: -1,
            start: 0,
            values_len: 0,
            values_capacity: 0,
            values: ptr::null_mut(),
            labels_len: 0,
            labels_capacity: 0,
            labels: ptr::null_mut(),
            variables_len: 0,
            variables_capacity: 0,
            variables: ptr::null_mut(),
        }
    }

    /// Create a [SavedDataReader] from a given [SavedData].
    ///
    /// This copies all the data in the [SavedData] out to C into a C
    /// compatiable format.
    pub fn new(data: &SavedData) -> Self {
        let mut var_values = btree_to_vec(&data.values, my_clone);

        let mut var_labels = btree_to_vec(&data.labels, my_to_le_bytes);

        let mut var_variables = btree_to_vec(&data.variables, my_to_raw_c_str_ptr);

        let out = Self {
            status: 1,
            start: data.start.unwrap().try_into().unwrap(),

            values_len: var_values.len().try_into().unwrap(),
            values_capacity: var_values.capacity().try_into().unwrap(),
            values: var_values.as_mut_ptr(),

            labels_len: var_labels.len().try_into().unwrap(),
            labels_capacity: var_labels.capacity().try_into().unwrap(),
            labels: var_labels.as_mut_ptr(),

            variables_len: var_variables.len().try_into().unwrap(),
            variables_capacity: var_variables.capacity().try_into().unwrap(),
            variables: var_variables.as_mut_ptr(),
        };
        // Make sure our vectors are not dropped while our new structure exists
        mem::forget(var_values);
        mem::forget(var_labels);
        mem::forget(var_variables);

        out
    }
}

/// Create a CString from the first element of the given tuple and then drop it
fn drop_first_tuple_member<T>(input: &(*mut i8, T)) {
    unsafe {
        drop(CString::from_raw(input.0));
    }
}

/// Create a CString from both elements of the given tuple and then drop them
fn drop_both_tuple_members(input: &(*mut i8, *mut i8)) {
    unsafe {
        drop(CString::from_raw(input.0));
        drop(CString::from_raw(input.1));
    }
}

/// Drops the vector made up of the given parts.
///
/// Calls "dropper" on each of the vector elements to drop any child elements of
/// each vector element which may need special dropping
fn vec_dropper<T>(ptr: *mut T, length: u64, capacity: u64, dropper: fn(&T)) {
    // recreate the vec
    let v = unsafe {
        Vec::from_raw_parts(
            ptr,
            length.try_into().unwrap(),
            capacity.try_into().unwrap(),
        )
    };
    // Call the dropper function (provided in an arg to this function) on each
    // element of the vector (giving a chance for sub-elements to be dropped)
    for x in v.iter() {
        dropper(x);
    }
    // drop the vec
    drop(v);
}

impl Drop for SavedDataReader {
    fn drop(&mut self) {
        vec_dropper(
            self.values,
            self.values_len,
            self.values_capacity,
            drop_first_tuple_member,
        );
        vec_dropper(
            self.labels,
            self.labels_len,
            self.labels_capacity,
            drop_first_tuple_member,
        );
        vec_dropper(
            self.variables,
            self.variables_len,
            self.variables_capacity,
            drop_both_tuple_members,
        );
    }
}
