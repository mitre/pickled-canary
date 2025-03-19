// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use super::super::jsonstructs as j;
use bitvec::prelude::*;

#[derive(Debug, Clone)]
pub struct MaskedValue<Endian: BitOrder> {
    pub value: BitVec<u8, Endian>,
    pub mask: BitVec<u8, Endian>,
}

impl<Endian: BitOrder> From<j::MaskedValue> for MaskedValue<Endian> {
    fn from(item: j::MaskedValue) -> Self {
        Self {
            value: BitVec::<_, Endian>::from_slice(&item.value),
            mask: BitVec::<_, Endian>::from_slice(&item.mask),
        }
    }
}
