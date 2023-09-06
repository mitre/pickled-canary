// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

use super::super::jsonstructs as j;
use super::{LookupType, Pattern};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use bitvec::prelude::*;
use core::convert::TryInto;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op<Endian: BitOrder + Clone> {
    Byte {
        value: u8,
    },
    MaskedByte {
        mask: u8,
        value: u8,
    },
    /// Notice that this op (unlike [Op::Byte] and [Op::MaskedByte]) does NOT
    /// consume the byte (aka: move on to the next byte if it matches). This is
    /// intended to be used as a pre-check before a [Op::Byte],
    /// [Op::LookupQuick], etc... (so that later instruction is still needed to
    /// consume the byte)
    ByteMultiNonconsuming {
        value: Vec<u8>,
    },
    Match {
        match_number: usize,
    },
    Jmp {
        dest: usize,
    },
    Split {
        dest1: usize,
        dest2: usize,
    },
    SplitMulti {
        dests: Vec<usize>,
    },
    SaveStart,
    Save {
        slot: usize,
    },
    Label {
        value: String,
    },
    AnyByte,
    /// Min and max are INCLUSIVE, so at least min bytes and at most exactly max
    /// bytes are consumed
    AnyByteSequence {
        min: usize,
        max: usize,
        interval: usize,
    },
    Lookup {
        data: Vec<LookupType<Endian>>,
    },
    LookupQuick {
        bytes: Vec<u8>,
        data: Vec<LookupType<Endian>>,
    },
    NegativeLookahead {
        pattern: Pattern<Endian>,
    },
}

impl<Endian: BitOrder + Clone> From<j::Op> for Op<Endian> {
    fn from(item: j::Op) -> Self {
        match item {
            j::Op::BYTE { value } => Self::Byte { value },
            j::Op::MASKEDBYTE { mask, value } => Self::MaskedByte { mask, value },
            j::Op::MATCH => Self::Match { match_number: 0 },
            j::Op::JMP { dest } => Self::Jmp { dest },
            j::Op::SPLIT { dest1, dest2 } => Self::Split { dest1, dest2 },
            j::Op::SPLITMULTI { dests } => Self::SplitMulti { dests },
            j::Op::SAVE { slot } => Self::Save { slot },
            j::Op::LABEL { value } => Self::Label { value },
            j::Op::ANYBYTE => Self::AnyByte,
            j::Op::ANYBYTESEQUENCE { min, max, interval } => {
                Self::AnyByteSequence { min, max, interval }
            }
            j::Op::LOOKUP { data } => {
                let data: Vec<LookupType<Endian>> = data.iter().map(|x| x.clone().into()).collect();

                // Look through our lookup values counting how many start with a 0xFF mask
                if data
                    .iter()
                    .filter(|x| match *x {
                        LookupType::MaskAndChoose {
                            mask: _,
                            choices: _,
                        } => false, // For now, don't bother if we have an un-aligned MaskAndChoose (we could implement this in the future)
                        LookupType::MaskAndChooseAligned { mask, choices: _ } => mask[0] == 0xff,
                        LookupType::MaskAndChooseu32 { mask, choices: _ } => {
                            mask.to_le_bytes()[3] == 0xFF
                        }
                    })
                    .count()
                    == data.len()
                {
                    // We get into this block if all our masks started with 0xFF.

                    // collect all the first bytes of our values (the things
                    // that must match because of the 0xFF mask) into a vector
                    // for quick matching
                    let mut bytes = vec![];
                    for val in data.iter() {
                        match val {
                            // We wont hit this first arm because we returned
                            // false on this match arm when counting if the mask
                            // started with 0xFF above
                            LookupType::MaskAndChoose {
                                mask: _,
                                choices: _,
                            } => todo!(),
                            LookupType::MaskAndChooseAligned { mask: _, choices } => {
                                for choice in choices {
                                    bytes.push(choice.value[0])
                                }
                            }
                            LookupType::MaskAndChooseu32 { mask: _, choices } => {
                                for choice in choices {
                                    bytes.push(choice.value.to_le_bytes()[3])
                                }
                            }
                        }
                    }
                    bytes.sort_unstable();
                    bytes.dedup();
                    Self::LookupQuick { bytes, data }
                } else {
                    Self::Lookup { data }
                }
            }
            j::Op::NEGATIVELOOKAHEAD { pattern } => Self::NegativeLookahead {
                pattern: pattern.into(),
            },
        }
    }
}

/// Returns orig+increment if orig >= above, else returns orig
fn get_incremented_if_above(orig: usize, increment: isize, above: usize) -> usize {
    if orig >= above {
        if increment.is_negative() {
            orig.checked_sub(increment.checked_neg().unwrap().try_into().unwrap())
                .unwrap()
        } else {
            orig.checked_add(increment.try_into().unwrap()).unwrap()
        }
    } else {
        orig
    }
}

impl<Endian: BitOrder + Clone> Op<Endian> {
    #[must_use]
    pub fn get_incremented(
        &self,
        increment: isize,
        new_match_number: Option<usize>,
        increment_tables: usize,
        above_index: usize,
    ) -> Op<Endian> {
        match self {
            Op::Jmp { dest } => Op::Jmp {
                dest: get_incremented_if_above(*dest, increment, above_index),
            },
            Op::Split { dest1, dest2 } => Op::Split {
                dest1: get_incremented_if_above(*dest1, increment, above_index),
                dest2: get_incremented_if_above(*dest2, increment, above_index),
            },
            Op::SplitMulti { dests } => {
                let mut new_dests = vec![];
                for dest in dests {
                    new_dests.push(get_incremented_if_above(*dest, increment, above_index));
                }
                Op::SplitMulti { dests: new_dests }
            }
            Op::Match { match_number: _ } => match new_match_number {
                Some(x) => Op::Match { match_number: x },
                None => self.clone(),
            },
            Op::Lookup { data } => {
                let mut new_data = vec![];
                for l in data {
                    new_data.push(l.get_clone_with_incremented_tables(increment_tables));
                }
                Op::Lookup { data: new_data }
            }
            Op::LookupQuick { bytes, data } => {
                let mut new_data = vec![];
                for l in data {
                    new_data.push(l.get_clone_with_incremented_tables(increment_tables));
                }
                Op::LookupQuick {
                    bytes: bytes.to_vec(),
                    data: new_data,
                }
            }
            // I coud use a "_ => self.clone()" for all of these... but I'd
            // prefer to have this match table break if a new Op is added
            Op::Byte { value: _ } => self.clone(),
            Op::MaskedByte { mask: _, value: _ } => self.clone(),
            Op::ByteMultiNonconsuming { value: _ } => self.clone(),
            Op::SaveStart => self.clone(),
            Op::Save { slot: _ } => self.clone(),
            Op::Label { value: _ } => self.clone(),
            Op::AnyByte => self.clone(),
            Op::AnyByteSequence {
                min: _,
                max: _,
                interval: _,
            } => self.clone(),
            Op::NegativeLookahead { pattern: _ } => self.clone(),
        }
    }

    pub fn decrement_tables_greater_than(&mut self, index: usize) {
        match self {
            Op::Lookup { data } => {
                for d in data {
                    d.decrement_tables_if_eq_greater_than(index);
                }
            }
            Op::LookupQuick { bytes: _, data } => {
                for d in data {
                    d.decrement_tables_if_eq_greater_than(index);
                }
            }
            // I coud use a "_ => self.clone()" for all of these... but I'd
            // prefer to have this match table break if a new Op is added
            Op::Jmp { dest: _ } => (),
            Op::Split { dest1: _, dest2: _ } => (),
            Op::SplitMulti { dests: _ } => (),
            Op::Match { match_number: _ } => (),
            Op::Byte { value: _ } => (),
            Op::MaskedByte { mask: _, value: _ } => (),
            Op::ByteMultiNonconsuming { value: _ } => (),
            Op::SaveStart => (),
            Op::Save { slot: _ } => (),
            Op::Label { value: _ } => (),
            Op::AnyByte => (),
            Op::AnyByteSequence {
                min: _,
                max: _,
                interval: _,
            } => (),
            Op::NegativeLookahead { pattern: _ } => (),
        }
    }

    pub fn get_used_tables(&self, out: &mut Vec<usize>) {
        match self {
            Op::Lookup { data } => {
                for d in data {
                    d.get_used_tables(out);
                }
            }
            Op::LookupQuick { bytes: _, data } => {
                for d in data {
                    d.get_used_tables(out);
                }
            }
            // I coud use a "_ => self.clone()" for all of these... but I'd
            // prefer to have this match table break if a new Op is added
            Op::Jmp { dest: _ } => (),
            Op::Split { dest1: _, dest2: _ } => (),
            Op::SplitMulti { dests: _ } => (),
            Op::Match { match_number: _ } => (),
            Op::Byte { value: _ } => (),
            Op::MaskedByte { mask: _, value: _ } => (),
            Op::ByteMultiNonconsuming { value: _ } => (),
            Op::SaveStart => (),
            Op::Save { slot: _ } => (),
            Op::Label { value: _ } => (),
            Op::AnyByte => (),
            Op::AnyByteSequence {
                min: _,
                max: _,
                interval: _,
            } => (),
            Op::NegativeLookahead { pattern: _ } => (),
        }
    }

    /// First return value is true if this op can fall through to the next step
    /// sequentially. Second return value is a list of other steps this op could
    /// end up at.
    pub fn get_next_steps(&self) -> (bool, Vec<usize>) {
        match self {
            Op::Byte { value: _ } => (true, vec![]),
            Op::MaskedByte { mask: _, value: _ } => (true, vec![]),
            Op::ByteMultiNonconsuming { value: _ } => (true, vec![]),
            Op::Match { match_number: _ } => (false, vec![]),
            Op::Jmp { dest } => (false, vec![*dest]),
            Op::Split { dest1, dest2 } => (false, vec![*dest1, *dest2]),
            Op::SplitMulti { dests } => (false, dests.clone()),
            Op::SaveStart => (true, vec![]),
            Op::Save { slot: _ } => (true, vec![]),
            Op::Label { value: _ } => (true, vec![]),
            Op::AnyByte => (true, vec![]),
            Op::AnyByteSequence {
                min: _,
                max: _,
                interval: _,
            } => (true, vec![]),
            Op::Lookup { data: _ } => (true, vec![]),
            Op::LookupQuick { bytes: _, data: _ } => (true, vec![]),
            Op::NegativeLookahead { pattern: _ } => (true, vec![]),
        }
    }

    // If this op has destinations (other than fall through) which point to step
    // old, update this destination to point to step new
    pub fn update_branches(&mut self, old: usize, new: usize) {
        match self {
            Op::Jmp { dest } => {
                if *dest == old {
                    *dest = new;
                }
            }
            Op::Split { dest1, dest2 } => {
                if *dest1 == old {
                    *dest1 = new;
                }
                if *dest2 == old {
                    *dest2 = new;
                }
            }
            Op::SplitMulti { dests } => {
                for dest in dests {
                    if *dest == old {
                        *dest = new
                    }
                }
            }
            // I coud use a "_ => self.clone()" for all of these... but I'd
            // prefer to have this match table break if a new Op is added
            Op::Lookup { data: _ } => (),
            Op::LookupQuick { bytes: _, data: _ } => (),
            Op::Match { match_number: _ } => (),
            Op::Byte { value: _ } => (),
            Op::MaskedByte { mask: _, value: _ } => (),
            Op::ByteMultiNonconsuming { value: _ } => (),
            Op::SaveStart => (),
            Op::Save { slot: _ } => (),
            Op::Label { value: _ } => (),
            Op::AnyByte => (),
            Op::AnyByteSequence {
                min: _,
                max: _,
                interval: _,
            } => (),
            Op::NegativeLookahead { pattern: _ } => (),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use super::*;
    use crate::bitstructs::{
        instruction_encoding_aligned::InstructionEncodingAligned,
        instruction_encoding_u32::InstructionEncodingu32, LookupType,
    };

    #[test]
    fn test_lookup_conversionu32() {
        let json_op: j::Op = serde_json::from_slice(
            r#"{
            "data": [
                {
                    "type": "MaskAndChooseu32",
                    "choices": [
                        {
                            "operands": [],
                            "value": [
                                0,
                                48,
                                160,
                                227
                            ]
                        }
                    ],
                    "mask": [
                        255,
                        255,
                        255,
                        255
                    ]
                }
            ],
            "type": "LOOKUP"
        }"#
            .as_bytes(),
        )
        .unwrap();
        let bin_op: Op<Msb0> = json_op.try_into().unwrap();

        let expected = Op::<Msb0>::LookupQuick {
            bytes: vec![0],
            data: vec![LookupType::MaskAndChooseu32 {
                mask: 0xFFFFFFFF,
                choices: vec![InstructionEncodingu32 {
                    value: 0x30a0e3,
                    operands: vec![],
                }],
            }],
        };
        assert_eq!(expected, bin_op);
    }

    #[test]
    fn test_lookup_conversion_aligned() {
        let json_op: j::Op = serde_json::from_slice(
            r#"{
            "data": [
                {
                    "type": "MaskAndChooseAligned",
                    "choices": [
                        {
                            "operands": [],
                            "value": [
                                48,
                                160,
                                227
                            ]
                        }
                    ],
                    "mask": [
                        255,
                        255,
                        255
                    ]
                }
            ],
            "type": "LOOKUP"
        }"#
            .as_bytes(),
        )
        .unwrap();
        let bin_op: Op<Msb0> = json_op.try_into().unwrap();

        let expected = Op::<Msb0>::LookupQuick {
            bytes: vec![48],
            data: vec![LookupType::MaskAndChooseAligned {
                mask: vec![0xFF, 0xFF, 0xFF],
                choices: vec![InstructionEncodingAligned {
                    value: vec![0x30, 0xa0, 0xe3],
                    operands: vec![],
                }],
            }],
        };
        assert_eq!(expected, bin_op);
    }
}
