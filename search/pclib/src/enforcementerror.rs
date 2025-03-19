// Copyright (C) 2025 The MITRE Corporation All Rights Reserved
pub struct EnforcementError {
    pub constraint_number: usize,
    pub error_type: EnforcementErrorType,
}

pub enum EnforcementErrorType {
    MultipleHits,
    XorFailure,
}
