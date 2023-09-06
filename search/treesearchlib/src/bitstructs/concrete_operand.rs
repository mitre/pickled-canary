// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

use alloc::string::String;

#[derive(Debug, Clone)]
pub enum ConcreteOperand {
    Field { var_id: String, name: String },
    Scalar { var_id: String, value: i64 },
    Address { var_id: String, value: i128 },
}
