// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Merkle Tree Certificate verification primitives.
//!
//! Implements the Merkle tree algorithms from
//! [draft-ietf-plants-merkle-tree-certs](https://github.com/davidben/merkle-tree-certs/blob/7fecd363ca8274b464fa9a585964d9818f919322/draft-ietf-plants-merkle-tree-certs.md).

mod builder;
pub mod checkpoint;
mod cosigner;
mod entry;
mod landmark;
pub mod storage;
mod subtree;
pub mod tile;
mod tree;
mod verifier;

pub use builder::MerkleTreeBuilder;
pub use cosigner::{
    build_signature_input, encode_cosignatures, verify_cosignature, verify_ml_dsa_cosignature,
    Cosigner, MlDsaCosigner,
};
pub use entry::{build_entry, build_mtc_cert, build_mtc_proof};
pub use landmark::{find_covering_subtrees, LandmarkSequence};
pub use storage::{CheckpointStore, LocalStore, TileStore};
pub use subtree::Subtree;
pub use tree::{evaluate_inclusion_proof, hash_leaf, hash_node, verify_consistency_proof};
pub use tree::{TreeHash, HASH_SIZE};
pub use verifier::{verify_mtc_cert, CosignerAlgorithm, TrustAnchor, TrustedCosigner, VerifyError};
