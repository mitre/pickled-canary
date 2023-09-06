use core::convert::TryFrom;
use core::ops::RangeBounds;

/// A wrapper struct which points to a slice of bits and maintains a base
/// address where those bits notionally start.
///
/// Indexing this struct returns the bits at that/those index(es).
///
/// Calling [`Self::get_range`] returns a new [AddressedBits] containing a
/// subset of the source [AddressedBits]
pub struct AddressedBits<'a> {
    base_address: i64,
    bits: &'a [u8],
}

/// Allow indexing into the bits this [AddressedBits] represents.
impl<'a, Idx> core::ops::Index<Idx> for AddressedBits<'a>
where
    Idx: core::slice::SliceIndex<[u8]>,
{
    type Output = Idx::Output;

    fn index(&self, index: Idx) -> &Self::Output {
        &self.bits[index]
    }
}

/// Allow conversion from a slice pointer into an [AddressedBits]
impl<'a> From<&'a [u8]> for AddressedBits<'a> {
    fn from(value: &'a [u8]) -> AddressedBits<'a> {
        Self {
            base_address: 0,
            bits: value,
        }
    }
}

impl<'a> AddressedBits<'a> {
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    pub fn get_base_address(&self) -> i64 {
        self.base_address
    }

    /// Get this [AddressedBits] as it's underlying u8 slice
    pub fn as_bits(&self) -> &'a [u8] {
        self.bits
    }

    /// Returns a new [AddressedBits] which is a subset of this [AddressedBits]
    pub fn get_range<R: core::slice::SliceIndex<[u8], Output = [u8]> + RangeBounds<usize>>(
        //
        &self,
        index: R,
    ) -> AddressedBits<'a> {
        let start = match index.start_bound() {
            core::ops::Bound::Included(x) => *x,
            core::ops::Bound::Excluded(x) => *x + 1,
            core::ops::Bound::Unbounded => 0,
        };
        Self {
            base_address: self.base_address + i64::try_from(start).unwrap(),
            bits: &self.bits[index],
        }
    }

    /// Create a new [AddressedBits] with the given `bits` at the given `base_address`
    pub fn new(bits: &'a [u8], base_address: i64) -> Self {
        Self { base_address, bits }
    }
}
