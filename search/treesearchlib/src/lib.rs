// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

#![feature(test)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
// This library is no_std, except when compiled in `test` mode.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod bitstructs;
pub mod jsonstructs;
pub use bitstructs as b;
pub use jsonstructs as j;
pub mod automata;
