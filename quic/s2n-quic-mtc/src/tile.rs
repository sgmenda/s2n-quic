// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tile serialization per https://c2sp.org/tlog-tiles
//!
//! Tiles are 256 hashes wide (8192 bytes when full). Partial tiles contain
//! 1-255 hashes. Level 0 tiles contain leaf hashes; higher levels contain
//! hashes of full tiles below.

use crate::tree::{TreeHash, HASH_SIZE};

pub const TILE_WIDTH: u64 = 256;
pub const FULL_TILE_SIZE: usize = TILE_WIDTH as usize * HASH_SIZE;

/// Compute the tile path for a given level and index.
/// e.g. level=0, index=1234067 → "tile/0/x001/x234/067"
//= specs/merkle-tree-certs/tlog-tiles.md#merkle-tree
//# `<L>` is the “level” of the tile, and MUST be a decimal ASCII integer between 0
//# and 63, with no additional leading zeroes.
//
//= specs/merkle-tree-certs/tlog-tiles.md#merkle-tree
//# It MUST be a non-negative
//# integer encoded into zero-padded 3-digit path elements.
//
//= specs/merkle-tree-certs/tlog-tiles.md#merkle-tree
//# All but the last path
//# element MUST begin with an `x`.
//
//= specs/merkle-tree-certs/tlog-tiles.md#merkle-tree
//# Full tiles MUST be exactly 256 hashes wide, or 8,192 bytes.
pub fn tile_path(level: u64, index: u64, width: Option<u64>) -> String {
    let idx_path = encode_tile_index(index);
    match width {
        Some(w) => format!("tile/{level}/{idx_path}.p/{w}"),
        None => format!("tile/{level}/{idx_path}"),
    }
}

/// Compute the entry bundle path for a given index.
pub fn entry_bundle_path(index: u64, width: Option<u64>) -> String {
    let idx_path = encode_tile_index(index);
    match width {
        Some(w) => format!("tile/entries/{idx_path}.p/{w}"),
        None => format!("tile/entries/{idx_path}"),
    }
}

/// Encode a tile index as zero-padded 3-digit path elements with 'x' prefix.
/// e.g. 1234067 → "x001/x234/067"
fn encode_tile_index(mut index: u64) -> String {
    if index == 0 {
        return "000".to_string();
    }
    let mut parts = Vec::new();
    while index > 0 {
        parts.push(format!("{:03}", index % 1000));
        index /= 1000;
    }
    parts.reverse();
    // All but last get 'x' prefix
    for i in 0..parts.len() - 1 {
        parts[i] = format!("x{}", parts[i]);
    }
    parts.join("/")
}

/// Serialize a tile (a sequence of hashes) to bytes.
pub fn serialize_tile(hashes: &[TreeHash]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(hashes.len() * HASH_SIZE);
    for h in hashes {
        buf.extend_from_slice(h);
    }
    buf
}

/// For a tree of size `n`, compute the tile coordinates needed at each level.
/// Returns Vec of (level, index, width) where width is None for full tiles
/// and Some(w) for partial tiles.
pub fn tiles_for_size(n: u64) -> Vec<(u64, u64, Option<u64>)> {
    let mut tiles = Vec::new();
    let mut size = n;
    let mut level = 0u64;
    while size > 0 {
        let full_tiles = size / TILE_WIDTH;
        let partial = size % TILE_WIDTH;
        for i in 0..full_tiles {
            tiles.push((level, i, None));
        }
        if partial > 0 {
            tiles.push((level, full_tiles, Some(partial)));
        }
        size = full_tiles; // next level has one entry per full tile below
        level += 1;
    }
    tiles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tile_index_encoding() {
        assert_eq!(encode_tile_index(0), "000");
        assert_eq!(encode_tile_index(1), "001");
        assert_eq!(encode_tile_index(999), "999");
        assert_eq!(encode_tile_index(1000), "x001/000");
        assert_eq!(encode_tile_index(1234067), "x001/x234/067");
    }

    #[test]
    fn tile_paths() {
        assert_eq!(tile_path(0, 5, None), "tile/0/005");
        assert_eq!(tile_path(0, 5, Some(112)), "tile/0/005.p/112");
        assert_eq!(tile_path(1, 0, Some(17)), "tile/1/000.p/17");
    }

    #[test]
    fn tiles_for_70000() {
        // From the spec: tree of 70,000 → 273 full L0, 1 partial L0 (w=112),
        // 1 full L1, 1 partial L1 (w=17), 1 partial L2 (w=1)
        let tiles = tiles_for_size(70_000);
        let full_l0 = tiles.iter().filter(|(l, _, w)| *l == 0 && w.is_none()).count();
        let partial_l0: Vec<_> = tiles.iter().filter(|(l, _, w)| *l == 0 && w.is_some()).collect();
        let full_l1 = tiles.iter().filter(|(l, _, w)| *l == 1 && w.is_none()).count();
        let partial_l1: Vec<_> = tiles.iter().filter(|(l, _, w)| *l == 1 && w.is_some()).collect();
        let partial_l2: Vec<_> = tiles.iter().filter(|(l, _, w)| *l == 2 && w.is_some()).collect();

        assert_eq!(full_l0, 273);
        assert_eq!(partial_l0.len(), 1);
        assert_eq!(partial_l0[0].2, Some(112));
        assert_eq!(full_l1, 1);
        assert_eq!(partial_l1.len(), 1);
        assert_eq!(partial_l1[0].2, Some(17));
        assert_eq!(partial_l2.len(), 1);
        assert_eq!(partial_l2[0].2, Some(1));
    }
}
