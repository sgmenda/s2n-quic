// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-memory Merkle tree builder for generating test data and proofs.

use crate::tree::{hash_leaf, hash_node, TreeHash};
use crate::Subtree;

/// An in-memory Merkle tree that supports appending leaves and generating
/// inclusion proofs. Mirrors BoringSSL's `MerkleTreeInMemory`.
pub struct MerkleTreeBuilder {
    /// `levels[i][j]` = hash of the complete subtree `[j*2^i, (j+1)*2^i)`.
    levels: Vec<Vec<TreeHash>>,
}

impl Default for MerkleTreeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTreeBuilder {
    pub fn new() -> Self {
        Self {
            levels: vec![vec![]],
        }
    }

    /// Append a raw entry (unhashed) to the tree.
    pub fn append(&mut self, entry: &[u8]) {
        let h = hash_leaf(entry);
        self.levels[0].push(h);
        self.update_levels();
    }

    /// Append a pre-hashed leaf to the tree.
    pub fn append_hash(&mut self, leaf_hash: TreeHash) {
        self.levels[0].push(leaf_hash);
        self.update_levels();
    }

    pub fn size(&self) -> u64 {
        self.levels[0].len() as u64
    }

    /// Get the node at `(level, index)`, i.e. the hash of
    /// `[index * 2^level, (index+1) * 2^level)`.
    pub fn get_node(&self, level: usize, index: u64) -> TreeHash {
        self.levels[level][index as usize]
    }

    /// Compute the hash of an arbitrary valid subtree.
    pub fn subtree_hash(&self, subtree: &Subtree) -> TreeHash {
        assert!(subtree.is_valid());
        assert!(subtree.end <= self.size());

        let mut start = subtree.start;
        let mut last = subtree.end - 1;

        // Start at the largest complete subtree on the right edge.
        let mut level = 0usize;
        while start != last && (last - start) & 1 == 1 {
            // Both start and last have their LSB set relative to each other,
            // meaning last is on the right edge of a complete subtree.
            level += 1;
            start >>= 1;
            last >>= 1;
        }
        // Actually: use trailing ones of (last - start) to find the level
        // Simpler approach: count trailing ones of (last - start)
        // Reset and redo properly:
        start = subtree.start;
        last = subtree.end - 1;
        level = trailing_ones(last - start);
        start >>= level;
        last >>= level;

        let mut ret = self.get_node(level, last);

        while start < last {
            if last & 1 == 1 {
                ret = hash_node(&self.get_node(level, last - 1), &ret);
            }
            level += 1;
            start >>= 1;
            last >>= 1;
        }

        ret
    }

    /// Generate an inclusion proof for `index` within `subtree`.
    pub fn inclusion_proof(&self, index: u64, subtree: &Subtree) -> Vec<u8> {
        assert!(subtree.is_valid());
        assert!(subtree.end <= self.size());
        assert!(subtree.contains_index(index));

        let mut proof = Vec::new();
        let mut start = subtree.start;
        let mut last = subtree.end - 1;
        let mut idx = index;
        let mut level = 0usize;

        while start < last {
            let neighbor = idx ^ 1;
            if neighbor < last {
                let h = self.get_node(level, neighbor);
                proof.extend_from_slice(&h);
            } else if neighbor == last {
                let h = self.subtree_hash(&Subtree::new(last << level, subtree.end));
                proof.extend_from_slice(&h);
            }
            level += 1;
            start >>= 1;
            idx >>= 1;
            last >>= 1;
        }
        proof
    }

    /// Root hash of the full tree `[0, size)`.
    pub fn root_hash(&self) -> TreeHash {
        let n = self.size();
        assert!(n > 0);
        self.subtree_hash(&Subtree::new(0, n))
    }

    fn update_levels(&mut self) {
        let n = self.size() as usize;
        let mut pairs = n / 2;
        let mut level = 1;
        while pairs > 0 {
            if level == self.levels.len() {
                self.levels.push(vec![]);
            }
            while self.levels[level].len() < pairs {
                let i = self.levels[level].len();
                let h = hash_node(
                    &self.levels[level - 1][2 * i],
                    &self.levels[level - 1][2 * i + 1],
                );
                self.levels[level].push(h);
            }
            level += 1;
            pairs /= 2;
        }
    }
}

fn trailing_ones(mut n: u64) -> usize {
    let mut count = 0;
    while n & 1 == 1 {
        n >>= 1;
        count += 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluate_inclusion_proof;

    #[test]
    fn build_and_verify() {
        let entries: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d", b"e"];
        let mut tree = MerkleTreeBuilder::new();
        for e in &entries {
            tree.append(e);
        }
        assert_eq!(tree.size(), 5);

        let full = Subtree::new(0, 5);
        let root = tree.root_hash();

        // Verify inclusion proof for each entry
        for i in 0..5u64 {
            let proof = tree.inclusion_proof(i, &full);
            let leaf_hash = hash_leaf(entries[i as usize]);
            let result = evaluate_inclusion_proof(&proof, i, &leaf_hash, &full);
            assert_eq!(result, Some(root), "failed for index {i}");
        }
    }

    #[test]
    fn subtree_proof() {
        let mut tree = MerkleTreeBuilder::new();
        for i in 0..16u8 {
            tree.append(&[i]);
        }

        // Verify inclusion in a subtree [8, 16)
        let subtree = Subtree::new(8, 16);
        let subtree_hash = tree.subtree_hash(&subtree);

        for i in 8..16u64 {
            let proof = tree.inclusion_proof(i, &subtree);
            let leaf_hash = hash_leaf(&[i as u8]);
            let result = evaluate_inclusion_proof(&proof, i, &leaf_hash, &subtree);
            assert_eq!(result, Some(subtree_hash), "failed for index {i}");
        }
    }
}
