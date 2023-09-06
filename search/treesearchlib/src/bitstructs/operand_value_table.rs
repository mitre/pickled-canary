// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Deref;

use bitvec::prelude::*;
use hashbrown::HashMap;

use super::super::jsonstructs as j;
use super::val_from_val_and_mask;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperandValueTable<Endian: BitOrder> {
    inner: HashMap<String, Vec<BitVec<u8, Endian>>>,
}

impl<Endian: BitOrder> From<HashMap<String, Vec<j::MaskedValue>>> for OperandValueTable<Endian> {
    fn from(item: HashMap<String, Vec<j::MaskedValue>>) -> Self {
        Self {
            inner: item
                .iter()
                .map(|(x, y)| {
                    let yy = y
                        .iter()
                        .map(|z| {
                            // eprintln!("V: {:?}\nM: {:?}", &z.value, &z.mask);
                            val_from_val_and_mask(
                                &BitVec::<_, Endian>::from_slice(&z.value),
                                &BitVec::<_, Endian>::from_slice(&z.mask),
                            )
                        })
                        .collect();
                    (x.clone(), yy)
                })
                .collect(),
        }
    }
}
impl<Endian: BitOrder> Deref for OperandValueTable<Endian> {
    type Target = HashMap<String, Vec<BitVec<u8, Endian>>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<Endian: BitOrder> OperandValueTable<Endian> {
    pub fn new(inner: HashMap<String, Vec<BitVec<u8, Endian>>>) -> Self {
        Self { inner }
    }
}
