// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use core::mem::size_of;

use bitvec::prelude::*;
use hashbrown::HashMap;

use super::{AddressedBits, LookupError, LookupResults};

#[derive(Clone)]
pub struct LookupCache<Endian: BitOrder> {
    inner: [HashMap<u64, Result<LookupResults, LookupError>>; size_of::<u64>()],
    max_cache_size: usize,
    sp_base_address_for_cache: i64,
}

#[inline(always)]
fn slice_to_u64(bits: &[u8], len: usize) -> u64 {
    let mut bits_rightsized = [0u8; size_of::<u64>()];
    bits_rightsized[..len].clone_from_slice(bits);
    u64::from_be_bytes(bits_rightsized)
}

impl<Endian: BitOrder> LookupCache<Endian> {
    pub fn new(max_cache_size: usize) -> Self {
        Self {
            inner: [
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
            ],
            max_cache_size,
            sp_base_address_for_cache: 0,
        }
    }

    pub fn add_to_cache(
        &mut self,
        bits: &AddressedBits,
        result: Result<LookupResults, LookupError>,
    ) {
        let len = bits.len();
        if len > size_of::<u64>() || len == 0 {
            return;
        }
        let cache_idx = len - 1;

        if bits.get_base_address() != self.sp_base_address_for_cache {
            // base changed... clear cache
            for x in self.inner.iter_mut() {
                x.clear();
            }
        }

        let bits_as_usize = slice_to_u64(bits.as_bits(), len);

        self.inner[cache_idx].insert(bits_as_usize, result);

        // Clear cache if it's gotten too big
        if self.inner[cache_idx].len() > self.max_cache_size {
            self.inner[cache_idx].clear();
        }
    }

    pub fn get_from_cache(
        &mut self,
        bits: &AddressedBits,
    ) -> Option<&Result<LookupResults, LookupError>> {
        let len = bits.len();
        if len >= size_of::<u64>()
            || len == 0
            || bits.get_base_address() != self.sp_base_address_for_cache
        {
            return None;
        }
        let cache_idx = len - 1;

        let bits_as_usize = slice_to_u64(bits.as_bits(), len);
        self.inner[cache_idx].get(&bits_as_usize)
    }
}
