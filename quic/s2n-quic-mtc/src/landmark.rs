// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Landmark sequence management.
//!
//! Implements the landmark allocation algorithm from
//! draft-ietf-plants-merkle-tree-certs Section 6.3.

use crate::Subtree;

/// Find one or two subtrees that cover the interval `[start, end)`.
///
/// Implements the "Arbitrary Intervals" procedure from spec Section 3.5.
pub fn find_covering_subtrees(start: u64, end: u64) -> Vec<Subtree> {
    assert!(start < end);
    if end - start == 1 {
        return vec![Subtree::new(start, end)];
    }
    let last = end - 1;
    let split = 63 - (start ^ last).leading_zeros(); // bit index of MSB difference
    let mask = (1u64 << split) - 1;
    let mid = last & !mask;
    // Actually: bit_length of (!start & mask)
    let left_split = if (!start & mask) == 0 {
        0
    } else {
        64 - (!start & mask).leading_zeros() as u64
    };
    let left_start = start & !((1u64 << left_split) - 1);
    vec![Subtree::new(left_start, mid), Subtree::new(mid, end)]
}

/// A landmark sequence tracking tree sizes for landmark certificate construction.
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-6.3.1
//# The sequence of tree sizes MUST
//# be append-only and strictly monotonically increasing.
//
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-6.3.1
//# Landmarks MUST be allocated such that, at any given time,
//# only active landmarks contain unexpired certificates.
//
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-6.3.2
//# It is RECOMMENDED that landmarks be allocated using the following
//# procedure:
pub struct LandmarkSequence {
    /// Maximum number of active landmarks.
    pub max_active_landmarks: usize,
    /// Tree sizes for landmarks, oldest to newest.
    /// Stores up to `max_active_landmarks + 1` entries (the extra one is the
    /// previous landmark needed to compute subtrees for the oldest active).
    landmarks: Vec<u64>,
}

impl LandmarkSequence {
    pub fn new(max_active_landmarks: usize) -> Self {
        // Landmark 0 is always tree size 0.
        Self {
            max_active_landmarks,
            landmarks: vec![0],
        }
    }

    /// Allocate a new landmark at the given tree size.
    /// The tree size must be strictly greater than the last landmark's.
    pub fn allocate(&mut self, tree_size: u64) {
        assert!(tree_size > *self.landmarks.last().unwrap());
        self.landmarks.push(tree_size);
        // Keep at most max_active_landmarks + 1 entries
        while self.landmarks.len() > self.max_active_landmarks + 1 {
            self.landmarks.remove(0);
        }
    }

    /// Number of active landmarks (not counting the retained previous one).
    pub fn num_active(&self) -> usize {
        // The first entry is the "previous" landmark, the rest are active.
        // But if we haven't filled up yet, all but the first are active.
        self.landmarks.len().saturating_sub(1)
    }

    /// Return all active landmark subtrees.
    ///
    /// Each landmark (except #0) defines 1-2 subtrees covering the interval
    /// between it and the previous landmark.
    pub fn active_subtrees(&self) -> Vec<Subtree> {
        let mut subtrees = Vec::new();
        for i in 1..self.landmarks.len() {
            let prev = self.landmarks[i - 1];
            let curr = self.landmarks[i];
            if prev < curr {
                subtrees.extend(find_covering_subtrees(prev, curr));
            }
        }
        subtrees
    }

    /// Find the landmark subtree(s) that contain a given leaf index.
    pub fn subtrees_containing(&self, index: u64) -> Vec<Subtree> {
        self.active_subtrees()
            .into_iter()
            .filter(|s| s.contains_index(index))
            .collect()
    }

    /// The most recent landmark's tree size.
    pub fn latest_tree_size(&self) -> u64 {
        *self.landmarks.last().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covering_subtrees_single() {
        let result = find_covering_subtrees(5, 6);
        assert_eq!(result, vec![Subtree::new(5, 6)]);
    }

    #[test]
    fn covering_subtrees_pair() {
        // Example from spec: [5, 13) → [4, 8) and [8, 13)
        let result = find_covering_subtrees(5, 13);
        assert_eq!(result, vec![Subtree::new(4, 8), Subtree::new(8, 13)]);
    }

    #[test]
    fn covering_subtrees_power_of_two() {
        // [0, 8) should give a single pair where left covers it
        let result = find_covering_subtrees(0, 8);
        // start == 0, last == 7, split = 2 (bit 2), mask = 3, mid = 4
        // left_split = bit_length(!0 & 3) = bit_length(3) = 2
        // left_start = 0 & !(3) = 0
        // → [0, 4) and [4, 8)
        assert_eq!(result, vec![Subtree::new(0, 4), Subtree::new(4, 8)]);
    }

    #[test]
    fn landmark_sequence_basic() {
        // 7-day certs, hourly landmarks → max_active = ceil(7*24/1) + 1 = 169
        // But let's use small numbers for testing
        let mut seq = LandmarkSequence::new(3);
        assert_eq!(seq.num_active(), 0);

        seq.allocate(100);
        assert_eq!(seq.num_active(), 1);

        seq.allocate(200);
        assert_eq!(seq.num_active(), 2);

        seq.allocate(300);
        assert_eq!(seq.num_active(), 3);

        // This should evict the oldest
        seq.allocate(400);
        assert_eq!(seq.num_active(), 3);

        // Active subtrees should cover [100, 200), [200, 300), [300, 400)
        let subtrees = seq.active_subtrees();
        // Each interval produces 1-2 subtrees
        assert!(!subtrees.is_empty());

        // Index 150 should be in a subtree from the [100, 200) interval
        let containing = seq.subtrees_containing(150);
        assert!(!containing.is_empty());

        // Index 50 should NOT be in any active subtree (it was evicted)
        let containing = seq.subtrees_containing(50);
        assert!(containing.is_empty());
    }

    #[test]
    fn landmark_subtrees_are_valid() {
        let mut seq = LandmarkSequence::new(5);
        seq.allocate(10);
        seq.allocate(25);
        seq.allocate(100);

        for subtree in seq.active_subtrees() {
            assert!(
                subtree.is_valid(),
                "subtree [{}, {}) is not valid",
                subtree.start,
                subtree.end
            );
        }
    }
}
