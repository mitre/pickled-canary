//! This module holds all of the data structures required to encode a [Pattern]
//! in JSON. This JSON form of things is later converted into a [binary
//! format](super::bitstructs) for effecient processing.

// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

use core::convert::TryInto;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MaskedValue {
    pub value: Vec<u8>,
    pub mask: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Pattern {
    pub steps: Vec<Op>,
    pub tables: Vec<HashMap<String, Vec<MaskedValue>>>,
}

fn one() -> usize {
    1 // same as return 1;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Op {
    BYTE {
        value: u8,
    },
    MASKEDBYTE {
        mask: u8,
        value: u8,
    },
    MATCH,
    JMP {
        dest: usize,
    },
    SPLIT {
        dest1: usize,
        dest2: usize,
    },
    SPLITMULTI {
        dests: Vec<usize>,
    },
    SAVE {
        slot: usize,
    },
    LABEL {
        value: String,
    },
    ANYBYTE,
    ANYBYTESEQUENCE {
        min: usize,
        max: usize,
        #[serde(default = "one")]
        interval: usize,
    },
    LOOKUP {
        data: Vec<LookupType>,
    },
    NEGATIVELOOKAHEAD {
        pattern: Pattern,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum LookupType {
    MaskAndChoose {
        choices: Vec<InstructionEncoding>,
        mask: Vec<u8>,
    },
    MaskAndChooseAligned {
        choices: Vec<InstructionEncodingAligned>,
        mask: Vec<u8>,
    },
    MaskAndChooseu32 {
        choices: Vec<InstructionEncodingu32>,
        mask: Vec<u8>,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InstructionEncoding {
    pub value: Vec<u8>,
    pub operands: Vec<OperandType>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InstructionEncodingAligned {
    pub value: Vec<u8>,
    pub operands: Vec<OperandType>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InstructionEncodingu32 {
    pub value: Vec<u8>,
    pub operands: Vec<OperandType>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum OperandType {
    Field {
        table_id: usize,
        mask: Vec<u8>,
        var_id: String,
    },
    Scalar {
        mask: Vec<u8>,
        expression: PatternExpression,
        var_id: String,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct TokenField {
    pub bigendian: bool,
    pub signbit: bool,
    pub bitstart: usize,
    pub bitend: usize,
    pub bytestart: usize,
    pub byteend: usize,
    pub shift: i64,
}

impl TokenField {
    /// Get the value this TokenField represents when applied to the given bytes
    ///
    /// This mirrors the process used in LookupDateExpressionSolver.java for a
    /// TokenField, which itself is modeled on the original Ghidra
    /// implementation of these things.
    pub fn get_value(&self, bytes: &[u8]) -> i64 {
        // Get the specific bytes for this tokenField from the given bytes input
        let size = self.byteend - self.bytestart + 1;
        if size > bytes.len() {
            panic!("Not enough bytes to read!");
        }
        let mut instruction_bytes = Vec::from(&bytes[self.bytestart..=self.byteend]);

        // Get a buffer of 0 bytes equal in length to the number of bytes we
        // need to add to instruction_bytes to make it the length of an i64
        let mut additional_bytes = vec![0; ((i64::BITS / 8) as usize) - instruction_bytes.len()];

        // Get the instruction_bytes as an i64 (appending or prepending
        // additional_bytes as needed by our curent endian)
        let mut instruction_as_i64 = if self.bigendian {
            instruction_bytes.splice(0..0, additional_bytes);
            i64::from_be_bytes(instruction_bytes.try_into().unwrap())
        } else {
            instruction_bytes.append(&mut additional_bytes);
            i64::from_le_bytes(instruction_bytes.try_into().unwrap())
        };

        // Adjust the starting bit if necessary
        instruction_as_i64 = instruction_as_i64
            .checked_shr(self.shift.try_into().unwrap())
            .unwrap();

        // Sign extend or zero-extend if necessary
        let sign_bit_index = self.bitend - self.bitstart;
        let mut mask: i64 = (!0i64) << sign_bit_index;
        if self.signbit {
            // This is sign extending
            if ((instruction_as_i64 >> sign_bit_index) & 1) != 0 {
                instruction_as_i64 | mask
            } else {
                instruction_as_i64 & !mask
            }
        } else {
            // This is zero extending (making our our bits higher than the sign bit are zero)
            mask <<= 1;
            instruction_as_i64 & !mask
        }
    }
}
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ContextField {
    pub signbit: bool,
    pub bitstart: usize,
    pub bitend: usize,
    pub bytestart: usize,
    pub byteend: usize,
    pub shift: i64,
}

impl ContextField {
    /// Get the value this ContextField represents when applied to the given bytes
    ///
    /// This mirrors the process used in LookupDateExpressionSolver.java for a
    /// ContextField, which itself is modeled on the original Ghidra
    /// implementation of these things.
    pub fn get_value(&self, bytes: &[u8]) -> i64 {
        // Get the specific bytes for this ContextField from the given bytes input
        let size = self.byteend - self.bytestart + 1;
        if size > bytes.len() {
            panic!("Not enough bytes to read!");
        }
        let mut instruction_bytes = Vec::from(&bytes[self.bytestart..=self.byteend]);

        // Get a buffer of 0 bytes equal in length to the number of bytes we
        // need to add to instruction_bytes to make it the length of an i64
        let additional_bytes = vec![0; ((i64::BITS / 8) as usize) - instruction_bytes.len()];

        // Get the instruction_bytes as an i64 (appending or prepending
        // additional_bytes as needed by our curent endian)
        instruction_bytes.splice(0..0, additional_bytes);
        let mut instruction_as_i64 = i64::from_be_bytes(instruction_bytes.try_into().unwrap());

        // Adjust the starting bit if necessary
        instruction_as_i64 = instruction_as_i64
            .checked_shr(self.shift.try_into().unwrap())
            .unwrap();

        // Sign extend or zero-extend if necessary
        let sign_bit_index = self.bitend - self.bitstart;
        let mut mask: i64 = (!0i64) << sign_bit_index;
        if self.signbit {
            // This is sign extending
            if ((instruction_as_i64 >> sign_bit_index) & 1) != 0 {
                instruction_as_i64 | mask
            } else {
                instruction_as_i64 & !mask
            }
        } else {
            // This is zero extending (making our our bits higher than the sign bit are zero)
            mask <<= 1;
            instruction_as_i64 & !mask
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct BinaryPatternExpressionChildren {
    left: Box<PatternExpression>,
    right: Box<PatternExpression>,
}

impl BinaryPatternExpressionChildren {
    pub fn get_values(&self, bits: &[u8], len: i64, sp_base_address: i64) -> (i64, i64) {
        (
            self.left.get_value(bits, len, sp_base_address),
            self.right.get_value(bits, len, sp_base_address),
        )
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "op")]
pub enum PatternExpression {
    Add {
        children: BinaryPatternExpressionChildren,
    },
    Sub {
        children: BinaryPatternExpressionChildren,
    },
    Mult {
        children: BinaryPatternExpressionChildren,
    },
    LeftShift {
        children: BinaryPatternExpressionChildren,
    },
    RightShift {
        children: BinaryPatternExpressionChildren,
    },
    And {
        children: BinaryPatternExpressionChildren,
    },
    Or {
        children: BinaryPatternExpressionChildren,
    },
    Xor {
        children: BinaryPatternExpressionChildren,
    },
    Div {
        children: BinaryPatternExpressionChildren,
    },
    Minus {
        child: Box<PatternExpression>,
    },
    Not {
        child: Box<PatternExpression>,
    },
    StartInstructionValue,
    EndInstructionValue,
    ConstantValue {
        value: i64,
    },
    OperandValue {
        offset: i64,
        child: Box<PatternExpression>,
    },
    TokenField {
        value: TokenField,
    },
    ContextField {
        value: ContextField,
    },
}

impl PatternExpression {
    pub fn get_value(&self, bits: &[u8], len: i64, sp_base_address: i64) -> i64 {
        match self {
            PatternExpression::Add { children } => {
                let (left_val, right_val) = children.get_values(bits, len, sp_base_address);
                left_val + right_val
            }
            PatternExpression::Sub { children } => {
                let (left_val, right_val) = children.get_values(bits, len, sp_base_address);
                left_val - right_val
            }
            PatternExpression::Mult { children } => {
                let (left_val, right_val) = children.get_values(bits, len, sp_base_address);
                left_val * right_val
            }
            PatternExpression::LeftShift { children } => {
                let (left_val, right_val) = children.get_values(bits, len, sp_base_address);
                left_val << right_val
            }
            PatternExpression::RightShift { children } => {
                let (left_val, right_val) = children.get_values(bits, len, sp_base_address);
                left_val >> right_val
            }
            PatternExpression::And { children } => {
                let (left_val, right_val) = children.get_values(bits, len, sp_base_address);
                left_val & right_val
            }
            PatternExpression::Or { children } => {
                let (left_val, right_val) = children.get_values(bits, len, sp_base_address);
                left_val | right_val
            }
            PatternExpression::Xor { children } => {
                let (left_val, right_val) = children.get_values(bits, len, sp_base_address);
                left_val ^ right_val
            }
            PatternExpression::Div { children } => {
                let (left_val, right_val) = children.get_values(bits, len, sp_base_address);
                left_val / right_val
            }
            PatternExpression::Minus { child } => -(child.get_value(bits, len, sp_base_address)),
            PatternExpression::Not { child } => !(child.get_value(bits, len, sp_base_address)),
            PatternExpression::StartInstructionValue => sp_base_address, //sp + sp_base_address,
            PatternExpression::EndInstructionValue => len + sp_base_address, //sp + len + sp_base_address,
            PatternExpression::ConstantValue { value } => *value,
            PatternExpression::OperandValue { offset, child } => {
                // TODO: Should len be adjusted here? Probably... See other
                // stuff done in the Java: ParserWalker.setOutOfBandState.
                // However we don't currently adjust this in Java either...
                let (_, offset_bits) = bits.split_at(*offset as usize);
                child.get_value(offset_bits, len, sp_base_address + *offset)
            }
            PatternExpression::TokenField { value } => value.get_value(bits),
            PatternExpression::ContextField { value } => value.get_value(bits),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_import_stuff() {
        let thing: PatternExpression = serde_json::from_str(
            "{
            \"op\": \"ConstantValue\",
            \"value\": 1
          }",
        )
        .unwrap();
        eprintln!("Thing: {:?}", thing);
        assert_eq!(PatternExpression::ConstantValue { value: 1 }, thing);
    }

    #[test]
    fn test_tf_get_value2() {
        let t = TokenField {
            bigendian: false,
            signbit: false,
            bitstart: 0,
            bitend: 31,
            bytestart: 0,
            byteend: 3,
            shift: 0,
        };

        assert_eq!(0x04030201, t.get_value(&[0x01, 0x02, 0x3, 0x4]));

        let t = TokenField {
            bigendian: true,
            signbit: false,
            bitstart: 0,
            bitend: 31,
            bytestart: 0,
            byteend: 3,
            shift: 0,
        };

        assert_eq!(0x01020304, t.get_value(&[0x01, 0x02, 0x3, 0x4]));

        let t = TokenField {
            bigendian: false,
            signbit: true,
            bitstart: 0,
            bitend: 23,
            bytestart: 0,
            byteend: 2,
            shift: 0,
        };

        // Arm LE BL instruction bytes:
        // the following is:
        // bl foo
        // Where foo is 0xc bytes before the start of the first byte listed here
        let arm_le_bl = &[0xfb, 0xff, 0xff, 0xeb];

        assert_eq!(-5, t.get_value(arm_le_bl));

        let one_bit_not_set = &[0xfc, 0xff, 0xff, 0xeb];

        assert_eq!(-4, t.get_value(one_bit_not_set));

        let t = TokenField {
            bigendian: false,
            signbit: true,
            bitstart: 0,
            bitend: 11,
            bytestart: 0,
            byteend: 1,
            shift: 0,
        };
        let ldr = &[0x04u8, 0x30, 0x9f, 0xe5];

        assert_eq!(4, t.get_value(ldr));
    }

    #[test]
    fn test_real_example() {
        // This is the expression generated for the destination of an arm thumb
        // bl instruction. The data we're feeding it is for a bl to 0x7e29 after
        // the address of the bl instruction.
        let test_expression: PatternExpression = serde_json::from_str(
            r#"
        {
            "op": "Add",
            "children": {
                "left": {
                    "op": "Add",
                    "children": {
                        "left": {"op": "StartInstructionValue"},
                        "right": {
                            "op": "ConstantValue",
                            "value": 4
                        }
                    }
                },
                "right": {
                    "op": "Or",
                    "children": {
                        "left": {
                            "op": "Or",
                            "children": {
                                "left": {
                                    "op": "Or",
                                    "children": {
                                        "left": {
                                            "op": "LeftShift",
                                            "children": {
                                                "left": {
                                                    "op": "Xor",
                                                    "children": {
                                                        "left": {
                                                            "op": "OperandValue",
                                                            "offset": 2,
                                                            "child": {
                                                                "op": "TokenField",
                                                                "value": {
                                                                    "bitend": 13,
                                                                    "shift": 5,
                                                                    "signbit": false,
                                                                    "bitstart": 13,
                                                                    "byteend": 1,
                                                                    "bigendian": false,
                                                                    "bytestart": 1
                                                                }
                                                            }
                                                        },
                                                        "right": {
                                                            "op": "ConstantValue",
                                                            "value": 1
                                                        }
                                                    }
                                                },
                                                "right": {
                                                    "op": "ConstantValue",
                                                    "value": 23
                                                }
                                            }
                                        },
                                        "right": {
                                            "op": "LeftShift",
                                            "children": {
                                                "left": {
                                                    "op": "Xor",
                                                    "children": {
                                                        "left": {
                                                            "op": "OperandValue",
                                                            "offset": 2,
                                                            "child": {
                                                                "op": "TokenField",
                                                                "value": {
                                                                    "bitend": 11,
                                                                    "shift": 3,
                                                                    "signbit": false,
                                                                    "bitstart": 11,
                                                                    "byteend": 1,
                                                                    "bigendian": false,
                                                                    "bytestart": 1
                                                                }
                                                            }
                                                        },
                                                        "right": {
                                                            "op": "ConstantValue",
                                                            "value": 1
                                                        }
                                                    }
                                                },
                                                "right": {
                                                    "op": "ConstantValue",
                                                    "value": 22
                                                }
                                            }
                                        }
                                    }
                                },
                                "right": {
                                    "op": "LeftShift",
                                    "children": {
                                        "left": {
                                            "op": "OperandValue",
                                            "offset": 0,
                                            "child": {
                                                "op": "TokenField",
                                                "value": {
                                                    "bitend": 9,
                                                    "shift": 0,
                                                    "signbit": false,
                                                    "bitstart": 0,
                                                    "byteend": 1,
                                                    "bigendian": false,
                                                    "bytestart": 0
                                                }
                                            }
                                        },
                                        "right": {
                                            "op": "ConstantValue",
                                            "value": 12
                                        }
                                    }
                                }
                            }
                        },
                        "right": {
                            "op": "LeftShift",
                            "children": {
                                "left": {
                                    "op": "OperandValue",
                                    "offset": 2,
                                    "child": {
                                        "op": "TokenField",
                                        "value": {
                                            "bitend": 10,
                                            "shift": 0,
                                            "signbit": false,
                                            "bitstart": 0,
                                            "byteend": 1,
                                            "bigendian": false,
                                            "bytestart": 0
                                        }
                                    }
                                },
                                "right": {
                                    "op": "ConstantValue",
                                    "value": 1
                                }
                            }
                        }
                    }
                }
            }
        }"#,
        )
        .unwrap();

        assert_eq!(
            0xe950,
            test_expression.get_value(&[0x07, 0xf0, 0x47, 0xff], 4, 0x6abe)
        );
    }
}
