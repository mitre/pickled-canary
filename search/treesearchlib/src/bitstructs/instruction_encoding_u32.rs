// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

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
        }
    }
}
impl<Endian: BitOrder> From<j::InstructionEncodingAligned> for InstructionEncodingu32<Endian> {
    fn from(item: j::InstructionEncodingAligned) -> Self {
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
        }
    }
}
impl<Endian: BitOrder> From<j::InstructionEncodingu32> for InstructionEncodingu32<Endian> {
    fn from(item: j::InstructionEncodingu32) -> Self {
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
}
