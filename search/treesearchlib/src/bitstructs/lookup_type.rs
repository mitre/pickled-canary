// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::string::ToString as _;
use alloc::vec::Vec;
use core::ops::Deref;

use bitvec::prelude::*;

use super::super::jsonstructs as j;
use super::AddressedBits;
use super::{
    ConcreteOperand, InstructionEncoding, InstructionEncodingAligned, InstructionEncodingTrait,
    InstructionEncodingu32, LookupCache, LookupError, LookupResults, OperandValueTable, SavedData,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupType<Endian: BitOrder> {
    MaskAndChoose {
        mask: BitVec<u8, Endian>,
        choices: Vec<InstructionEncoding<Endian>>,
    },
    MaskAndChooseAligned {
        mask: Vec<u8>,
        choices: Vec<InstructionEncodingAligned<Endian>>,
    },
    MaskAndChooseu32 {
        mask: u32,
        choices: Vec<InstructionEncodingu32<Endian>>,
    },
}

impl<Endian: BitOrder> From<j::LookupType> for LookupType<Endian> {
    fn from(item: j::LookupType) -> Self {
        match item {
            j::LookupType::MaskAndChoose { mask, choices } => {
                if mask.len() == 4 {
                    // This will panic if our mask is not 4 bytes... but that's ok, we just checked
                    let mut bits = [0u8; 4];
                    bits.copy_from_slice(&mask[0..4]);

                    Self::MaskAndChooseu32 {
                        choices: choices
                            .iter()
                            .map(|x| {
                                let out: InstructionEncodingu32<Endian> = x.clone().into();
                                out
                            })
                            .collect(),

                        mask: u32::from_be_bytes(bits),
                    }
                } else {
                    Self::MaskAndChooseAligned {
                        choices: choices
                            .iter()
                            .map(|x| {
                                let out: InstructionEncodingAligned<Endian> = x.clone().into();
                                out
                            })
                            .collect(),
                        mask,
                    }
                    // The following is the most generic case... but we never generate it so... commenting out for now
                    // Self::MaskAndChoose {
                    //     choices: choices
                    //         .iter()
                    //         .map(|x| {
                    //             let out: InstructionEncoding<Endian> = x.clone().into();
                    //             out
                    //         })
                    //         .collect(),
                    //     mask: BitVec::<_, Endian>::from_slice(&mask).unwrap(),
                    // }
                }
            }
            j::LookupType::MaskAndChooseAligned { choices, mask } => Self::MaskAndChooseAligned {
                choices: choices
                    .iter()
                    .map(|x| {
                        let out: InstructionEncodingAligned<Endian> = x.clone().into();
                        out
                    })
                    .collect(),
                mask,
            },
            j::LookupType::MaskAndChooseu32 { choices, mask } => {
                // This will panic if our mask is not 4 bytes... but that's ok
                let mut bits = [0u8; 4];
                bits.copy_from_slice(&mask[0..4]);

                Self::MaskAndChooseu32 {
                    choices: choices
                        .iter()
                        .map(|x| {
                            let out: InstructionEncodingu32<Endian> = x.clone().into();
                            out
                        })
                        .collect(),

                    mask: u32::from_be_bytes(bits),
                }
            }
        }
    }
}

/// Try to update the given store to contain the given value for the given
/// var_id. Returns an error if the given value does not match the value already
/// present for the given var_id.
fn try_update<T: PartialEq>(
    store: &mut BTreeMap<String, T>,
    var_id: &String,
    value: T,
) -> Result<(), LookupError> {
    // If we already have a saved value for this
    // var_id (eg: Q#) then make sure the value we
    // have here matches it
    if let Some(existing_value) = store.get(var_id) {
        // We have an existing value

        // But it doesn't match... return None
        if *existing_value != value {
            return Err(LookupError::OperandsDontMatch);
        }
        // Else the value matches, so we'll fall through to
        // continue to check other operands
    } else {
        // No already saved variable found, save this value
        store.insert(var_id.clone(), value);
    }
    Ok(())
}

impl<Endian: BitOrder + Clone> LookupType<Endian> {
    pub fn do_lookup_with_saved_state(
        &self,
        cache: &mut LookupCache<Endian>,
        bits: &AddressedBits,
        tables: &[OperandValueTable<Endian>],
        saved: &mut SavedData,
    ) -> Result<LookupResults, LookupError> {
        let unchecked_result = self.do_lookup_cached(cache, bits, tables)?;
        for resolved_operand in &unchecked_result.operands {
            match resolved_operand {
                ConcreteOperand::Field { var_id, name } => {
                    try_update(&mut saved.variables, var_id, name.clone())?;
                }
                ConcreteOperand::Scalar { var_id, value } => {
                    try_update(&mut saved.values, var_id, *value)?;
                }
                ConcreteOperand::Address { var_id, value } => {
                    try_update(&mut saved.labels, var_id, *value)?;
                }
            }
        }
        Ok(unchecked_result)
    }

    pub fn do_lookup_with_saved_state_rc(
        &self,
        cache: &mut LookupCache<Endian>,
        bits: &AddressedBits,
        tables: &[OperandValueTable<Endian>],
        saved: &mut Rc<SavedData>,
    ) -> Result<LookupResults, LookupError> {
        check_result(self.do_lookup_cached(cache, bits, tables)?, saved)
    }

    pub fn do_lookup_with_saved_state_rc_no_cache(
        &self,
        _cache: &mut LookupCache<Endian>,
        bits: &AddressedBits,
        tables: &[OperandValueTable<Endian>],
        saved: &mut Rc<SavedData>,
    ) -> Result<LookupResults, LookupError> {
        check_result(self.do_lookup(bits, tables)?, saved)
    }

    pub fn do_lookup_cached(
        &self,
        cache: &mut LookupCache<Endian>,
        bits: &AddressedBits,
        tables: &[OperandValueTable<Endian>],
    ) -> Result<LookupResults, LookupError> {
        match cache.get_from_cache(bits) {
            Some(x) => (*x).clone(),
            None => {
                let result = self.do_lookup(bits, tables);
                cache.add_to_cache(bits, result.clone());
                result
            }
        }
    }

    pub fn do_lookup(
        &self,
        bits: &AddressedBits,
        tables: &[OperandValueTable<Endian>],
    ) -> Result<LookupResults, LookupError> {
        match self {
            LookupType::MaskAndChoose { mask, choices } => {
                let size = match get_slice_size_from_bit_vec::<Endian>(mask) {
                    Some(x) => x,
                    None => return Err(LookupError::FailedToGetSliceSize),
                };

                if bits.len() < size {
                    return Err(LookupError::NotEnoughBytes);
                }

                let subject_full_bits = bits.get_range(..size);

                let subject_full = BitVec::<_, Endian>::from_slice(subject_full_bits.as_bits());

                // Originally had the following line, but the following is
                // a faster way to build subject (fewer allocations)
                // (see benchmarks in treesearchtool/tests/cachetest.rs)
                //
                // let subject = subject_full.clone() & mask.clone();
                let mut mask_iter = mask.iter();
                let subject: BitVec<u8, Endian> = subject_full
                    .iter()
                    .map(|x| x.deref() & mask_iter.next().as_deref().unwrap())
                    .collect();

                for choice in choices {
                    if choice.value == subject {
                        // eprintln!("Found match with value {:?}", choice.value);
                        if let Ok(operands) = choice.get_operands(
                            &subject_full,
                            tables,
                            size,
                            subject_full_bits.get_base_address(),
                        ) {
                            return Ok(LookupResults { size, operands });
                        }
                    }
                }
                Err(LookupError::InstructionBitsNotFound)
            }
            LookupType::MaskAndChooseAligned { mask, choices } => {
                let size = mask.len();

                if bits.len() < size {
                    return Err(LookupError::NotEnoughBytes);
                }

                let subject_full_bits = bits.get_range(..size);

                let subject_full = subject_full_bits.as_bits().to_vec();

                let mut subject = subject_full.clone();
                subject
                    .iter_mut()
                    .zip(mask.iter())
                    .for_each(|(sub_byte, mask_byte)| *sub_byte &= mask_byte);

                for choice in choices {
                    if choice.value == subject {
                        // eprintln!("Found match with value {:?}", choice.value);

                        let subject_full_bitvec =
                            BitVec::<_, Endian>::from_slice(subject_full.as_slice());
                        if let Ok(operands) = choice.get_operands(
                            &subject_full_bitvec,
                            tables,
                            size,
                            subject_full_bits.get_base_address(),
                        ) {
                            return Ok(LookupResults { size, operands });
                        }
                    }
                }
                Err(LookupError::InstructionBitsNotFound)
            }
            LookupType::MaskAndChooseu32 { mask, choices } => {
                if bits.len() < 4 {
                    return Err(LookupError::NotEnoughBytes);
                }
                let mut local_bits = [0u8; 4];
                local_bits.copy_from_slice(&bits[0..4]);
                let subject_u32 = u32::from_be_bytes(local_bits);

                let subject_masked = subject_u32 & *mask;

                for choice in choices {
                    if choice.value == subject_masked {
                        // eprintln!("Found match with value {:?}", choice.value);

                        let subject_full_bitvec = BitVec::<_, Endian>::from_slice(&bits[..4]);
                        if let Ok(operands) = choice.get_operands(
                            &subject_full_bitvec,
                            tables,
                            4,
                            bits.get_base_address(),
                        ) {
                            return Ok(LookupResults { size: 4, operands });
                        }
                    }
                }
                Err(LookupError::InstructionBitsNotFound)
            }
        }
    }

    #[must_use]
    pub fn get_clone_with_incremented_tables(&self, increment_tables: usize) -> Self {
        match self {
            LookupType::MaskAndChoose { mask, choices } => LookupType::MaskAndChoose {
                mask: mask.clone(),
                choices: choices
                    .iter()
                    .map(|x| x.get_table_incremented_clone(increment_tables))
                    .collect(),
            },
            LookupType::MaskAndChooseAligned { mask, choices } => {
                LookupType::MaskAndChooseAligned {
                    mask: mask.clone(),
                    choices: choices
                        .iter()
                        .map(|x| x.get_table_incremented_clone(increment_tables))
                        .collect(),
                }
            }
            LookupType::MaskAndChooseu32 { mask, choices } => LookupType::MaskAndChooseu32 {
                mask: *mask,
                choices: choices
                    .iter()
                    .map(|x| x.get_table_incremented_clone(increment_tables))
                    .collect(),
            },
        }
    }

    pub fn decrement_tables_if_eq_greater_than(&mut self, index: usize) {
        match self {
            LookupType::MaskAndChoose { mask: _, choices } => {
                for choice in choices {
                    choice.decrement_tables_if_eq_greater_than(index)
                }
            }
            LookupType::MaskAndChooseAligned { mask: _, choices } => {
                for choice in choices {
                    choice.decrement_tables_if_eq_greater_than(index)
                }
            }
            LookupType::MaskAndChooseu32 { mask: _, choices } => {
                for choice in choices {
                    choice.decrement_tables_if_eq_greater_than(index)
                }
            }
        }
    }

    pub fn get_used_tables(&self, out: &mut Vec<usize>) {
        match self {
            LookupType::MaskAndChoose { mask: _, choices } => {
                for choice in choices {
                    choice.get_used_tables(out)
                }
            }
            LookupType::MaskAndChooseAligned { mask: _, choices } => {
                for choice in choices {
                    choice.get_used_tables(out)
                }
            }
            LookupType::MaskAndChooseu32 { mask: _, choices } => {
                for choice in choices {
                    choice.get_used_tables(out)
                }
            }
        }
    }
}

/// Checks if the given store contains the given value for the given var_id.
/// Returns an error if the given value does not match the value already present
/// for the given var_id. Returns None if no value was found, returns Some(())
/// if value found and matched
fn try_check<T: PartialEq + Clone>(
    store: &BTreeMap<String, T>,
    var_id: &String,
    value: T,
) -> Result<Option<()>, LookupError> {
    // If we already have a saved value for this
    // var_id (eg: Q#) then make sure the value we
    // have here matches it
    if let Some(existing_value) = store.get(var_id) {
        // We have an existing value

        // But it doesn't match... return None
        if *existing_value != value {
            // eprintln!(
            //     "Rejected operand value: {} -> {} != {}",
            //     var_id, existing_value, name
            // );
            return Err(LookupError::OperandsDontMatch);
        }
        // Else the value matches, tell our caller we're good
        Ok(Some(()))
    } else {
        // No value found, tell our caller to add it to the store
        Ok(None)
    }
}

fn check_result(
    unchecked_result: LookupResults,
    saved: &mut Rc<SavedData>,
) -> Result<LookupResults, LookupError> {
    //let new_saved = Rc::make_mut(saved);
    for resolved_operand in &unchecked_result.operands {
        match resolved_operand {
            ConcreteOperand::Field { var_id, name } => {
                if try_check(&saved.variables, var_id, name.to_string())?.is_none() {
                    // No already saved variable found, save this value
                    Rc::make_mut(saved)
                        .variables
                        .insert(var_id.clone(), name.to_string());
                }
            }
            ConcreteOperand::Scalar { var_id, value } => {
                if try_check(&saved.values, var_id, *value)?.is_none() {
                    // No already saved variable found, save this value
                    Rc::make_mut(saved).values.insert(var_id.clone(), *value);
                }
            }
            ConcreteOperand::Address { var_id, value } => {
                if try_check(&saved.labels, var_id, *value)?.is_none() {
                    // No already saved variable found, save this value
                    Rc::make_mut(saved).labels.insert(var_id.clone(), *value);
                }
            }
        }
    }
    Ok(unchecked_result)
}

fn get_slice_size_from_bit_vec<Endian: BitOrder>(src: &BitVec<u8, Endian>) -> Option<usize> {
    let len = src.len();
    let mut out = len.checked_div(8)?;
    if let Some(x) = len.checked_rem(8) {
        if x > 0 {
            out += 1;
        }
    }
    Some(out)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_get_slice_size_from_bit_vec() {
        let subject = BitVec::<u8, Msb0>::from_slice(&[0u8, 40, 40, 40, 0]);
        let result = get_slice_size_from_bit_vec(&subject);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 5);
    }
}
