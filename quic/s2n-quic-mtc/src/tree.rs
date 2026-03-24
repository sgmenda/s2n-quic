// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Merkle tree hash primitives and proof verification.
//!
//! Hash definitions from RFC 9162 Section 2.1.1.
//! Inclusion proof evaluation from draft-ietf-plants-merkle-tree-certs Section 3.3.2.
//! Consistency proof verification from draft-ietf-plants-merkle-tree-certs Section 3.4.3.

use crate::Subtree;
use aws_lc_rs::digest;

pub const HASH_SIZE: usize = 32; // SHA-256
pub type TreeHash = [u8; HASH_SIZE];

/// HASH(0x00 || entry) — leaf hash per RFC 9162 Section 2.1.1.
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-7.2
//# contents the TBSCertificateLogEntry.  Let entry_hash be the hash
//# of the entry, MTH({entry}) = HASH(0x00 || entry), as defined in
//# Section 2.1.1 of [RFC9162].
pub fn hash_leaf(entry: &[u8]) -> TreeHash {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(&[0x00]);
    ctx.update(entry);
    let d = ctx.finish();
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(d.as_ref());
    out
}

/// HASH(0x01 || left || right) — interior node hash per RFC 9162 Section 2.1.1.
pub fn hash_node(left: &TreeHash, right: &TreeHash) -> TreeHash {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(&[0x01]);
    ctx.update(left);
    ctx.update(right);
    let d = ctx.finish();
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(d.as_ref());
    out
}

/// Consume the next HASH_SIZE bytes from a proof slice.
fn next_proof_hash(proof: &mut &[u8]) -> Option<TreeHash> {
    if proof.len() < HASH_SIZE {
        return None;
    }
    let mut h = [0u8; HASH_SIZE];
    h.copy_from_slice(&proof[..HASH_SIZE]);
    *proof = &proof[HASH_SIZE..];
    Some(h)
}

/// Evaluate a subtree inclusion proof.
///
/// Given `inclusion_proof` for entry `index` with hash `entry_hash` of subtree
/// `[start, end)`, returns the expected subtree hash.
///
/// Implements draft-ietf-plants-merkle-tree-certs Section 3.3.2.
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-7.2
//# Let expected_subtree_hash be the result of evaluating the
//# MTCProof's inclusion_proof for entry index, with hash entry_hash,
//# of the subtree described by the MTCProof's start and end, following
//# the procedure in Section 3.3.2.
pub fn evaluate_inclusion_proof(
    inclusion_proof: &[u8],
    index: u64,
    entry_hash: &TreeHash,
    subtree: &Subtree,
) -> Option<TreeHash> {
    // Step 1: validate inputs
    if !subtree.is_valid() || !subtree.contains_index(index) {
        return None;
    }

    // Step 2: set fn and sn relative to subtree
    let mut fn_ = index - subtree.start;
    let mut sn = subtree.size() - 1;

    // Step 3
    let mut r = *entry_hash;

    // Step 4: consume proof hashes
    let mut proof = inclusion_proof;
    while !proof.is_empty() {
        let p = next_proof_hash(&mut proof)?;

        // Step 4.1
        if sn == 0 {
            return None;
        }

        // Step 4.2
        if (fn_ & 1) == 1 || fn_ == sn {
            // Step 4.2.1
            r = hash_node(&p, &r);
            // Step 4.2.2: right-shift until LSB(fn) is set
            while (fn_ & 1) == 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            // Step 4.2 otherwise
            r = hash_node(&r, &p);
        }

        // Step 4.3
        fn_ >>= 1;
        sn >>= 1;
    }

    // Step 5
    if sn != 0 {
        return None;
    }

    // Step 6
    Some(r)
}

/// Verify a subtree consistency proof.
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-7.2
//# The relying party MUST continue to perform
//# other checks, such as checking expiry.
pub fn verify_consistency_proof(
    n: u64,
    subtree: &Subtree,
    proof: &[u8],
    node_hash: &TreeHash,
    root_hash: &TreeHash,
) -> bool {
    match evaluate_consistency_proof(n, subtree, proof, node_hash) {
        Some(computed_root) => computed_root == *root_hash,
        None => false,
    }
}

/// Evaluate a subtree consistency proof, returning the computed root hash.
///
/// This is the inner function that returns the computed root hash rather than
/// comparing it, matching boringssl's API shape.
fn evaluate_consistency_proof(
    n: u64,
    subtree: &Subtree,
    proof: &[u8],
    node_hash: &TreeHash,
) -> Option<TreeHash> {
    // Step 1
    if !subtree.is_valid() || n < subtree.end {
        return None;
    }

    // Step 2
    let mut fn_ = subtree.start;
    let mut sn = subtree.end - 1;
    let mut tn = n - 1;

    // Steps 3-4
    if sn == tn {
        // Step 3: right-shift until fn == sn
        while fn_ != sn {
            fn_ >>= 1;
            sn >>= 1;
            tn >>= 1;
        }
    } else {
        // Step 4: right-shift until fn == sn or LSB(sn) is not set
        while fn_ != sn && (sn & 1) == 1 {
            fn_ >>= 1;
            sn >>= 1;
            tn >>= 1;
        }
    }

    // Steps 5-6
    let mut proof = proof;
    let (mut fr, mut sr) = if fn_ == sn {
        // Step 5
        (*node_hash, *node_hash)
    } else {
        // Step 6
        let first = next_proof_hash(&mut proof)?;
        (first, first)
    };

    // Step 7
    while !proof.is_empty() {
        let c = next_proof_hash(&mut proof)?;

        // Step 7.1
        if tn == 0 {
            return None;
        }

        // Step 7.2
        if (sn & 1) == 1 || sn == tn {
            // Step 7.2.1
            if fn_ < sn {
                fr = hash_node(&c, &fr);
            }
            // Step 7.2.2
            sr = hash_node(&c, &sr);
            // Step 7.2.3: right-shift until LSB(sn) is set
            while (sn & 1) == 0 {
                fn_ >>= 1;
                sn >>= 1;
                tn >>= 1;
            }
        } else {
            // Step 7.3
            sr = hash_node(&sr, &c);
        }

        // Step 7.4
        fn_ >>= 1;
        sn >>= 1;
        tn >>= 1;
    }

    // Step 8
    if tn != 0 || fr != *node_hash {
        return None;
    }

    Some(sr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_leaf_empty() {
        // SHA-256(0x00) = known value
        let h = hash_leaf(b"");
        // 0x00 prefix + empty = SHA256(0x00)
        assert_eq!(h.len(), HASH_SIZE);
        // Sanity: not all zeros
        assert_ne!(h, [0u8; HASH_SIZE]);
    }

    #[test]
    fn hash_node_deterministic() {
        let left = hash_leaf(b"a");
        let right = hash_leaf(b"b");
        let h1 = hash_node(&left, &right);
        let h2 = hash_node(&left, &right);
        assert_eq!(h1, h2);
        // Order matters
        let h3 = hash_node(&right, &left);
        assert_ne!(h1, h3);
    }

    /// Build a simple in-memory Merkle tree and verify inclusion proofs.
    #[test]
    fn inclusion_proof_small_tree() {
        // Build a tree with 4 leaves: d[0], d[1], d[2], d[3]
        let entries: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        let leaves: Vec<TreeHash> = entries.iter().map(|e| hash_leaf(e)).collect();

        // Level 1
        let n01 = hash_node(&leaves[0], &leaves[1]);
        let n23 = hash_node(&leaves[2], &leaves[3]);
        // Root
        let root = hash_node(&n01, &n23);

        let full_tree = Subtree::new(0, 4);

        // Inclusion proof for index 0: [leaves[1], n23]
        let mut proof = Vec::new();
        proof.extend_from_slice(&leaves[1]);
        proof.extend_from_slice(&n23);
        let result = evaluate_inclusion_proof(&proof, 0, &leaves[0], &full_tree);
        assert_eq!(result, Some(root));

        // Inclusion proof for index 2: [leaves[3], n01]
        let mut proof = Vec::new();
        proof.extend_from_slice(&leaves[3]);
        proof.extend_from_slice(&n01);
        let result = evaluate_inclusion_proof(&proof, 2, &leaves[2], &full_tree);
        assert_eq!(result, Some(root));

        // Wrong entry hash should produce different root
        let wrong = hash_leaf(b"wrong");
        let result = evaluate_inclusion_proof(&proof, 2, &wrong, &full_tree);
        assert_ne!(result, Some(root));
    }

    /// Verify inclusion proof for a non-power-of-2 tree (5 elements).
    #[test]
    fn inclusion_proof_non_power_of_two() {
        let entries: Vec<&[u8]> = vec![b"0", b"1", b"2", b"3", b"4"];
        let leaves: Vec<TreeHash> = entries.iter().map(|e| hash_leaf(e)).collect();

        // Build tree: split(5) = 4, so left = [0,4), right = [4,5)
        let n01 = hash_node(&leaves[0], &leaves[1]);
        let n23 = hash_node(&leaves[2], &leaves[3]);
        let n0123 = hash_node(&n01, &n23);
        // Right side is just leaves[4]
        let root = hash_node(&n0123, &leaves[4]);

        let full_tree = Subtree::new(0, 5);

        // Inclusion proof for index 4 (rightmost): [n0123]
        let mut proof = Vec::new();
        proof.extend_from_slice(&n0123);
        let result = evaluate_inclusion_proof(&proof, 4, &leaves[4], &full_tree);
        assert_eq!(result, Some(root));

        // Inclusion proof for index 0: [leaves[1], n23, leaves[4]]
        let mut proof = Vec::new();
        proof.extend_from_slice(&leaves[1]);
        proof.extend_from_slice(&n23);
        proof.extend_from_slice(&leaves[4]);
        let result = evaluate_inclusion_proof(&proof, 0, &leaves[0], &full_tree);
        assert_eq!(result, Some(root));
    }

    /// Test consistency proof: a subtree [0,4) is consistent with a tree of 5.
    #[test]
    fn consistency_proof_basic() {
        let entries: Vec<&[u8]> = vec![b"0", b"1", b"2", b"3", b"4"];
        let leaves: Vec<TreeHash> = entries.iter().map(|e| hash_leaf(e)).collect();

        let n01 = hash_node(&leaves[0], &leaves[1]);
        let n23 = hash_node(&leaves[2], &leaves[3]);
        let n0123 = hash_node(&n01, &n23);
        let root5 = hash_node(&n0123, &leaves[4]);

        let subtree = Subtree::new(0, 4);

        // Consistency proof for [0,4) in tree of 5: [leaves[4]]
        // The subtree [0,4) is full and directly contained, so fn==sn after
        // step 3. The proof just needs the right sibling.
        let mut proof = Vec::new();
        proof.extend_from_slice(&leaves[4]);
        assert!(verify_consistency_proof(
            5, &subtree, &proof, &n0123, &root5
        ));

        // Wrong node_hash should fail
        let wrong = hash_leaf(b"wrong");
        assert!(!verify_consistency_proof(5, &subtree, &proof, &wrong, &root5));
    }

    /// Invalid inputs should return None / false.
    #[test]
    fn invalid_inputs() {
        let h = hash_leaf(b"x");

        // Invalid subtree
        assert_eq!(
            evaluate_inclusion_proof(&[], 0, &h, &Subtree::new(5, 3)),
            None
        );

        // Index out of range
        assert_eq!(
            evaluate_inclusion_proof(&[], 5, &h, &Subtree::new(0, 4)),
            None
        );

        // Consistency: n < end
        assert!(!verify_consistency_proof(
            3,
            &Subtree::new(0, 4),
            &[],
            &h,
            &h
        ));
    }
}
