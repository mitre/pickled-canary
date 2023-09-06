// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

use alloc::vec::Vec;
use core::clone::Clone;

use bitvec::prelude::*;

use super::super::jsonstructs as j;
use super::instruction_encoding::InstructionEncodingTrait;
use super::OperandType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionEncodingAligned<Endian: BitOrder> {
    pub value: Vec<u8>,
    pub operands: Vec<OperandType<Endian>>,
}

impl<Endian: BitOrder> From<j::InstructionEncoding> for InstructionEncodingAligned<Endian> {
    fn from(item: j::InstructionEncoding) -> Self {
        Self {
            value: item.value.clone(),
            operands: item
                .operands
                .iter()
                .map(|x| {
                    let out: OperandType<Endian> = x.clone().into();
                    out
                })
                .collect(),
        }
    }
}
impl<Endian: BitOrder> From<j::InstructionEncodingAligned> for InstructionEncodingAligned<Endian> {
    fn from(item: j::InstructionEncodingAligned) -> Self {
        Self {
            value: item.value.clone(),
            operands: item
                .operands
                .iter()
                .map(|x| {
                    let out: OperandType<Endian> = x.clone().into();
                    out
                })
                .collect(),
        }
    }
}

impl<Endian: BitOrder + Clone> InstructionEncodingTrait<Endian>
    for InstructionEncodingAligned<Endian>
{
    fn get_operand_options(&self) -> &Vec<OperandType<Endian>> {
        &self.operands
    }

    fn get_operand_options_mut(&mut self) -> &mut Vec<OperandType<Endian>> {
        &mut self.operands
    }
}
