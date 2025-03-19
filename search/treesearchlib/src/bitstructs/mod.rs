//! This module contains all the data structures associated with a [Pattern] in
//! its binary format (the JSON equivalants are found in
//! [jsonstructs](super::jsonstructs)) along with their methods.

// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

pub use self::instruction_encoding::{InstructionEncoding, InstructionEncodingTrait};
use self::instruction_encoding_aligned::InstructionEncodingAligned;
use self::instruction_encoding_u32::InstructionEncodingu32;
pub mod instruction_encoding;
pub mod instruction_encoding_aligned;
pub mod instruction_encoding_u32;
use crate::automata::thread::SavedData;
use bitvec::prelude::*;

mod masked_value;
pub use masked_value::MaskedValue;
mod pattern;
pub use pattern::Pattern;
mod op;
pub use op::Op;
mod lookup_type;
pub use lookup_type::LookupType;
mod lookup_cache;
pub use lookup_cache::LookupCache;
mod lookup_results;
pub use lookup_results::{LookupError, LookupResults};
mod operand_value_table;
pub use operand_value_table::OperandValueTable;
mod operand_type;
pub use operand_type::OperandType;
mod concrete_operand;
pub use concrete_operand::ConcreteOperand;
mod addressed_bits;
pub use addressed_bits::AddressedBits;

/// Gets gets a bitvec of only the masked bits within data (removes all bits to the left or right of the mask extent)
pub fn val_from_val_and_mask<Endian: BitOrder>(
    data_full: &BitVec<u8, Endian>,
    mask_full: &BitVec<u8, Endian>,
) -> BitVec<u8, Endian> {
    let data_full = data_full.clone();
    let mask_full = mask_full.clone();

    // eprintln!("mask: {:?}", &mask_full);
    // eprintln!("data: {:?}", &data_full);

    if data_full.len() != mask_full.len() {
        panic!("Mask and data must be the same length!");
    }

    // Make sure our mask has at least one one
    if mask_full.count_ones() == 0 {
        return BitVec::<u8, Endian>::new();
    }

    // The following "unwraps" are safe because we know we have at least one b/c of previous check
    let mask_bits_s = &mask_full[mask_full.first_one().unwrap()..mask_full.last_one().unwrap() + 1];
    let data_bits_s = &data_full[mask_full.first_one().unwrap()..mask_full.last_one().unwrap() + 1];

    // I don't understand why I cannot simply do data_bits_s & mask_bits_s ... but I cannot, so I make new BitVecs
    let mask_bits = BitVec::<u8, Endian>::from_bitslice(mask_bits_s);
    let data_bits = BitVec::<u8, Endian>::from_bitslice(data_bits_s);

    let masked_data: BitVec<u8, Endian> = data_bits & mask_bits;

    BitVec::<u8, Endian>::from_bitslice(&masked_data)
}

#[cfg(test)]
pub mod tests {
    use hashbrown::HashMap;

    use crate::j::{PatternExpression, TokenField};

    use super::super::jsonstructs as j;
    use super::*;

    #[test]
    fn test_do_lookup() {
        let l = LookupType::MaskAndChoose {
            mask: BitVec::<u8, Msb0>::from_slice(&[0xffu8, 0x0, 0xff, 0x00]),
            choices: vec![InstructionEncoding {
                value: BitVec::<u8, Msb0>::from_slice(&[0xa2u8, 0x0, 0x55, 0x00]),
                operands: vec![],
                context: None,
            }],
        };

        l.do_lookup(&[0xa2u8, 0x77, 0x55, 0x12].as_slice().into(), &[])
            .unwrap();

        assert!(l
            .do_lookup(&[0x11u8, 0x77, 0x55, 0x12].as_slice().into(), &[],)
            .is_err());
    }

    pub fn get_test_data() -> (InstructionEncoding<Msb0>, Vec<OperandValueTable<Msb0>>) {
        let mut values_one = HashMap::new();
        values_one.insert(
            "aaa".to_string(),
            vec![j::MaskedValue {
                value: vec![0x1u8],
                mask: vec![0xfu8],
            }],
        );
        values_one.insert(
            "bbb".to_string(),
            vec![j::MaskedValue {
                value: vec![0x2u8],
                mask: vec![0xfu8],
            }],
        );
        values_one.insert(
            "ccc".to_string(),
            vec![
                j::MaskedValue {
                    value: vec![0x3u8],
                    mask: vec![0xfu8],
                },
                j::MaskedValue {
                    value: vec![0x4u8],
                    mask: vec![0xfu8],
                },
            ],
        );

        (
            InstructionEncoding {
                value: BitVec::<u8, Msb0>::from_slice(&[0xfbu8, 0x0, 0x0, 0xfa]),
                operands: vec![
                    OperandType::Field {
                        mask: BitVec::<u8, Msb0>::from_slice(&[0x00u8, 0xF, 0x0, 0x00]),
                        table_id: 0,
                        var_id: "Q1".to_string(),
                    },
                    OperandType::Scalar {
                        mask: BitVec::<u8, Msb0>::from_slice(&[0x00u8, 0x0, 0xF, 0x00]),
                        expression: PatternExpression::TokenField {
                            value: TokenField {
                                bigendian: false,
                                signbit: false,
                                bitstart: 0,
                                bitend: 8,
                                bytestart: 2,
                                byteend: 2,
                                shift: 0,
                            },
                        },
                        var_id: "Q2".to_string(),
                    },
                    OperandType::Scalar {
                        mask: BitVec::<u8, Msb0>::from_slice(&[0x00u8, 0x0, 0xF, 0x00]),
                        expression: PatternExpression::ConstantValue { value: 7 },
                        var_id: ":Q3".to_string(),
                    },
                ],
                context: None,
            },
            vec![values_one.into()],
        )
    }

    pub fn check_operands_results(results: Vec<ConcreteOperand>, expected_op: &str) {
        assert_eq!(results.len(), 3);
        match results.first().unwrap() {
            ConcreteOperand::Field { var_id, name } => {
                assert_eq!(name, expected_op);
                assert_eq!(*var_id, "Q1");
            }
            ConcreteOperand::Scalar {
                value: _,
                var_id: _,
            } => panic!("Shouldn't get a scalar"),
            ConcreteOperand::Address {
                value: _,
                var_id: _,
            } => panic!("Shouldn't get an address"),
        }

        match results.get(1).unwrap() {
            ConcreteOperand::Field { var_id: _, name: _ } => panic!("Shouldn't get a Field"),
            ConcreteOperand::Scalar { value, var_id } => {
                assert_eq!(*value, 4);
                assert_eq!(*var_id, "Q2");
            }
            ConcreteOperand::Address {
                value: _,
                var_id: _,
            } => panic!("Shouldn't get a Address"),
        }

        match results.get(2).unwrap() {
            ConcreteOperand::Field { var_id: _, name: _ } => panic!("Shouldn't get a Field"),
            ConcreteOperand::Scalar {
                value: _,
                var_id: _,
            } => {
                panic!("Shouldn't get a scalar")
            }
            ConcreteOperand::Address { value, var_id } => {
                assert_eq!(*value, 7);
                assert_eq!(*var_id, "Q3")
            }
        }
    }

    #[test]
    fn test_get_operands() {
        let (ie, tables) = get_test_data();

        let results = ie
            .get_operands(
                &BitVec::<u8, Msb0>::from_slice(&[0x00u8, 0x1, 0x4, 0x00]),
                &tables,
                4,
                0,
            )
            .unwrap();
        check_operands_results(results, "aaa");
    }

    #[test]
    fn test_get_all_together() {
        let (ie, tables) = get_test_data();

        let l = LookupType::MaskAndChoose {
            mask: BitVec::<u8, Msb0>::from_slice(&[0xffu8, 0x0, 0x00, 0xff]),
            choices: vec![ie],
        };

        let results = l
            .do_lookup(&[0xfb, 0x1, 0x04, 0xfa].as_slice().into(), &tables)
            .unwrap();
        eprintln!("Results: {:?}", results);
        check_operands_results(results.operands, "aaa");
    }

    /// This test exercises the enforcement of Q1/var_id constraints
    #[test]
    fn test_get_all_together_multiple_lookups() {
        let (ie, tables) = get_test_data();

        let mut saved = SavedData::new();
        let l = LookupType::MaskAndChoose {
            mask: BitVec::<u8, Msb0>::from_slice(&[0xffu8, 0x0, 0x00, 0xff]),
            choices: vec![ie],
        };

        let mut cache = LookupCache::new(500);

        let results = l
            .do_lookup_with_saved_state(
                &mut cache,
                &[0xfb, 0x3, 0x04, 0xfa].as_slice().into(),
                &tables,
                &mut saved,
            )
            .unwrap();

        check_operands_results(results.operands, "ccc");

        // This tests again using the same "saved" data but with our other value
        // for "ccc"
        let results = l
            .do_lookup_with_saved_state(
                &mut cache,
                &[0xfb, 0x4, 0x04, 0xfa].as_slice().into(),
                &tables,
                &mut saved,
            )
            .unwrap();
        check_operands_results(results.operands, "ccc");

        // This tests again using the same "saved" data but with a "Q1" value of
        // "aaa" which should fail
        assert!(l
            .do_lookup_with_saved_state(
                &mut cache,
                &[0xfb, 0x1, 0x04, 0xfa].as_slice().into(),
                &tables,
                &mut saved,
            )
            .is_err());
    }
}
