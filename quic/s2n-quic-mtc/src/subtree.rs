// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Subtree definition from draft-ietf-plants-merkle-tree-certs, Section 3.1.
//!
//! A subtree of a Merkle Tree over n elements is defined by a half-open
//! interval [start, end) where:
//!   - 0 <= start < end <= n
//!   - start is a multiple of BIT_CEIL(end - start)

/// A subtree of a Merkle tree, identified by the half-open interval
/// `[start, end)` of leaf indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Subtree {
    pub start: u64,
    pub end: u64,
}

impl Subtree {
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// Number of elements in the subtree.
    pub fn size(&self) -> u64 {
        self.end - self.start
    }

    /// Whether `[start, end)` specifies a valid subtree.
    ///
    /// A subtree must be a non-empty interval where `start` is a multiple of
    /// `BIT_CEIL(end - start)`. This ensures the subtree has no ragged left
    /// edge.
    //= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-6.1
    //= type=implication
    //# The TBSCertificate's serialNumber MUST contain the zero-based index
    //
    //= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-5.1
    //# SHA-256 [SHS]
    //# is RECOMMENDED.
    pub fn is_valid(&self) -> bool {
        if self.start >= self.end {
            return false;
        }
        let n = self.size();
        // start must be a multiple of bit_ceil(n).
        // bit_ceil(n) is the smallest power of 2 >= n.
        let alignment = n.next_power_of_two();
        self.start % alignment == 0
    }

    /// Split the subtree into left and right halves that share no interior
    /// nodes. Returns the split point k such that left = [start, k) and
    /// right = [k, end).
    ///
    /// Uses the largest power of 2 smaller than size as the split offset,
    /// matching RFC 9162 Section 2.1.1.
    pub fn split(&self) -> u64 {
        let n = self.size();
        if n < 2 {
            return self.end;
        }
        // Largest power of 2 strictly less than n.
        // bit_floor(n-1) gives the highest set bit of (n-1), which is the
        // largest power of 2 <= n-1, i.e. strictly less than n.
        let k = 1u64 << (63 - (n - 1).leading_zeros());
        self.start + k
    }

    pub fn left(&self) -> Self {
        Self::new(self.start, self.split())
    }

    pub fn right(&self) -> Self {
        Self::new(self.split(), self.end)
    }

    pub fn contains_index(&self, index: u64) -> bool {
        self.start <= index && index < self.end
    }

    pub fn contains(&self, other: &Subtree) -> bool {
        self.start <= other.start && other.end <= self.end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validity() {
        // Valid subtrees
        assert!(Subtree::new(0, 1).is_valid());
        assert!(Subtree::new(0, 5).is_valid());
        assert!(Subtree::new(0, 8).is_valid());
        assert!(Subtree::new(4, 8).is_valid());
        assert!(Subtree::new(8, 12).is_valid());
        assert!(Subtree::new(8, 16).is_valid());

        // Invalid: empty or backwards
        assert!(!Subtree::new(0, 0).is_valid());
        assert!(!Subtree::new(5, 3).is_valid());

        // Invalid: ragged left edge
        // [3, 5) has size 2, bit_ceil(2) = 2, 3 % 2 != 0
        assert!(!Subtree::new(3, 5).is_valid());
        // [1, 3) has size 2, bit_ceil(2) = 2, 1 % 2 != 0
        assert!(!Subtree::new(1, 3).is_valid());
        // [2, 7) has size 5, bit_ceil(5) = 8, 2 % 8 != 0
        assert!(!Subtree::new(2, 7).is_valid());
    }

    #[test]
    fn split() {
        // Size 1: split returns end (no split possible)
        assert_eq!(Subtree::new(0, 1).split(), 1);

        // Size 7: largest power of 2 < 7 is 4
        assert_eq!(Subtree::new(0, 7).split(), 4);

        // Size 8: largest power of 2 < 8 is 4
        assert_eq!(Subtree::new(0, 8).split(), 4);

        // Size 5 starting at 8: split at 8+4=12
        assert_eq!(Subtree::new(8, 13).split(), 12);
    }
}
