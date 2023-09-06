// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

use alloc::vec::Vec;
use core::fmt;

use super::ConcreteOperand;

#[derive(Debug, Clone)]
pub struct LookupResults {
    pub size: usize,
    pub operands: Vec<ConcreteOperand>,
}

#[derive(Debug, Clone)]
pub enum LookupError {
    OperandsDontMatch,
    FailedToGetSliceSize,
    NotEnoughBytes,
    InstructionBitsNotFound,
}

impl fmt::Display for LookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use LookupError::*;
        match self {
            OperandsDontMatch => write!(f, "Operand doesn't match existing value"),
            FailedToGetSliceSize => write!(f, "Failed to get slice size from bitvec"),
            NotEnoughBytes => write!(f, "Not enough bytes to possibly match"),
            InstructionBitsNotFound => {
                write!(f, "MaskAndChoose had no choice matching current bits")
            }
        }
    }
}
