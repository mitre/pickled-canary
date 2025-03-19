// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use alloc::vec::Vec;
use core::clone::Clone;

use bitvec::prelude::*;

use super::super::jsonstructs as j;
use super::instruction_encoding::InstructionEncodingTrait;
use super::OperandType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionEncodingu32<Endian: BitOrder> {
    pub value: u32,
    pub operands: Vec<OperandType<Endian>>,
    pub context: Option<Vec<u8>>,
}

impl<Endian: BitOrder> From<j::InstructionEncoding> for InstructionEncodingu32<Endian> {
    fn from(item: j::InstructionEncoding) -> Self {
        let mut bits = [0u8; 4];
        bits.copy_from_slice(&item.value[0..4]);
        Self {
            value: u32::from_be_bytes(bits),
            operands: item
                .operands
                .iter()
                .map(|x| {
                    let out: OperandType<Endian> = x.clone().into();
                    out
                })
                .collect(),
            context: item
                .context
                .map(|x| x.into_iter().flat_map(u32::to_be_bytes).collect()),
        }
    }
}

impl<Endian: BitOrder + Clone> InstructionEncodingTrait<Endian> for InstructionEncodingu32<Endian> {
    fn get_operand_options(&self) -> &Vec<OperandType<Endian>> {
        &self.operands
    }

    fn get_operand_options_mut(&mut self) -> &mut Vec<OperandType<Endian>> {
        &mut self.operands
    }

    fn get_context(&self) -> &Option<Vec<u8>> {
        &self.context
    }
}
