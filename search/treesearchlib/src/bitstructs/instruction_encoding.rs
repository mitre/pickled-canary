// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use alloc::string::ToString as _;
use alloc::vec;
use alloc::vec::Vec;
use core::clone::Clone;
use core::convert::TryInto;
use core::fmt;

use bitvec::prelude::*;

use super::super::jsonstructs as j;
use super::val_from_val_and_mask;
use super::ConcreteOperand;
use super::OperandType;
use super::OperandValueTable;

#[derive(Debug)]
pub enum OperandExtractionError<Endian: BitOrder> {
    OperandNotFoundInTable {
        operand: BitVec<u8, Endian>,
        table_id: usize,
    },
}

impl<Endian: BitOrder> fmt::Display for OperandExtractionError<Endian> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use OperandExtractionError::*;
        match self {
            OperandNotFoundInTable { operand, table_id } => write!(
                f,
                "Operand not found in specified table [operand={:?}, table={}]",
                operand, table_id
            ),
        }
    }
}

pub trait InstructionEncodingTrait<Endian: BitOrder + Clone>: Clone {
    fn get_operand_options(&self) -> &Vec<OperandType<Endian>>;
    fn get_operand_options_mut(&mut self) -> &mut Vec<OperandType<Endian>>;
    fn get_context(&self) -> &Option<Vec<u8>>;

    /// Compute the value(s) of the operand(s) represented by the given `bits`.
    ///
    /// # Note:
    /// This may produced unexpected output if the alignment of these bits (as
    /// specified by `sp_base_address` is not as expected in a running system.
    /// Specifically, if the operand value depends on masking some part of the
    /// address of the current instruction, and that address is misaligned
    /// during our computation of the operands value we may produce unexpected
    /// output.
    fn get_operands(
        &self,
        bits: &BitVec<u8, Endian>,
        tables: &[OperandValueTable<Endian>],
        // Size of the instruction containing these operands (in bytes)
        size: usize,
        sp_base_address: i64,
    ) -> Result<Vec<ConcreteOperand>, OperandExtractionError<Endian>> {
        let mut out = vec![];
        for operand in self.get_operand_options() {
            out.push(match operand {
                OperandType::Field {
                    table_id,
                    mask,
                    var_id,
                } => {
                    let operand = val_from_val_and_mask(bits, mask);
                    let outt = tables
                        .get(*table_id)
                        .unwrap()
                        .iter()
                        .find_map(|(key, value)| {
                            if value.iter().any(|x| {
                                // eprintln!("{:?} ==?\n{:?}\n{:?}\n", *x, operand, *x == operand);
                                *x == operand
                            }) {
                                Some(ConcreteOperand::Field {
                                    var_id: var_id.to_string(),
                                    name: key.clone(),
                                })
                            } else {
                                None
                            }
                        });

                    // eprintln!("Outt: {:?}", outt);

                    if outt.is_none() {
                        return Err(OperandExtractionError::OperandNotFoundInTable {
                            operand,
                            table_id: *table_id,
                        });
                    }
                    outt.unwrap()
                }
                OperandType::Scalar {
                    mask: _,
                    expression,
                    var_id,
                } => {
                    let v = expression.get_value(
                        bits.as_raw_slice(),
                        self.get_context(),
                        size.try_into().unwrap(),
                        sp_base_address,
                    );

                    if var_id.starts_with(':') {
                        ConcreteOperand::Address {
                            var_id: var_id.strip_prefix(':').unwrap().to_string(),
                            value: v as i128,
                        }
                    } else {
                        ConcreteOperand::Scalar {
                            var_id: var_id.clone(),
                            value: v,
                        }
                    }
                }
            });
        }
        Ok(out)
    }

    #[must_use]
    fn get_table_incremented_clone(&self, increment_tables: usize) -> Self
    where
        Self: core::marker::Sized,
    {
        let mut new = (*self).clone();
        for x in new.get_operand_options_mut() {
            if let OperandType::Field {
                table_id,
                mask: _,
                var_id: _,
            } = x
            {
                *table_id += increment_tables;
            }
        }
        new
    }

    fn decrement_tables_if_eq_greater_than(&mut self, index: usize) {
        for operand in self.get_operand_options_mut() {
            operand.decrement_table_if_eq_greater_than(index)
        }
    }

    fn get_used_tables(&self, out: &mut Vec<usize>) {
        for operand in self.get_operand_options() {
            let table = operand.get_table();
            if let Some(t) = table {
                out.push(t);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionEncoding<Endian: BitOrder> {
    pub value: BitVec<u8, Endian>,
    pub operands: Vec<OperandType<Endian>>,
    pub context: Option<Vec<u8>>,
}

impl<Endian: BitOrder> From<j::InstructionEncoding> for InstructionEncoding<Endian> {
    fn from(item: j::InstructionEncoding) -> Self {
        Self {
            value: BitVec::<_, Endian>::from_slice(&item.value),
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

impl<Endian: BitOrder + Clone> InstructionEncodingTrait<Endian> for InstructionEncoding<Endian> {
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
