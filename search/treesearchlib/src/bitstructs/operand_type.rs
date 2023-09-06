// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

use alloc::string::String;

use super::super::jsonstructs as j;
use bitvec::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperandType<Endian: BitOrder> {
    Field {
        table_id: usize,
        mask: BitVec<u8, Endian>,
        var_id: String,
    },
    Scalar {
        mask: BitVec<u8, Endian>,
        expression: j::PatternExpression,
        var_id: String,
    },
}

impl<Endian: BitOrder> From<j::OperandType> for OperandType<Endian> {
    fn from(item: j::OperandType) -> Self {
        match item {
            j::OperandType::Field {
                table_id,
                mask,
                var_id,
            } => Self::Field {
                table_id,
                mask: BitVec::<_, Endian>::from_slice(&mask),
                var_id,
            },
            j::OperandType::Scalar {
                mask,
                expression,
                var_id,
            } => Self::Scalar {
                mask: BitVec::<_, Endian>::from_slice(&mask),
                expression,
                var_id,
            },
        }
    }
}

impl<Endian: BitOrder> OperandType<Endian> {
    pub fn decrement_table_if_eq_greater_than(&mut self, index: usize) {
        if let OperandType::Field {
            table_id,
            mask: _,
            var_id: _,
        } = self
        {
            if *table_id >= index {
                *table_id -= 1;
            }
        }
    }

    pub fn get_table(&self) -> Option<usize> {
        if let OperandType::Field {
            table_id,
            mask: _,
            var_id: _,
        } = self
        {
            Some(*table_id)
        } else {
            None
        }
    }
}
