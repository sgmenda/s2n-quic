// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pluggable storage backends for tile and checkpoint persistence.

use std::io;
use std::path::{Path, PathBuf};

/// Storage for immutable Merkle tree tiles.
pub trait TileStore {
    fn put_tile(&self, path: &str, data: &[u8]) -> io::Result<()>;
    fn get_tile(&self, path: &str) -> io::Result<Vec<u8>>;
    fn tile_exists(&self, path: &str) -> bool;
}

/// Storage for the mutable checkpoint with compare-and-swap semantics.
pub trait CheckpointStore {
    fn get(&self) -> io::Result<Option<String>>;
    /// Write new checkpoint. Returns Ok(true) if successful, Ok(false) if
    /// the current checkpoint doesn't match `expected` (CAS failure).
    fn compare_and_swap(&self, expected: Option<&str>, new: &str) -> io::Result<bool>;
}

/// Local filesystem implementation of both stores.
pub struct LocalStore {
    base: PathBuf,
}

impl LocalStore {
    pub fn new(base: impl AsRef<Path>) -> io::Result<Self> {
        let base = base.as_ref().to_path_buf();
        std::fs::create_dir_all(&base)?;
        std::fs::create_dir_all(base.join("tile"))?;
        std::fs::create_dir_all(base.join("tile").join("entries"))?;
        Ok(Self { base })
    }

    fn tile_path(&self, path: &str) -> PathBuf {
        self.base.join(path)
    }

    fn checkpoint_path(&self) -> PathBuf {
        self.base.join("checkpoint")
    }
}

impl TileStore for LocalStore {
    fn put_tile(&self, path: &str, data: &[u8]) -> io::Result<()> {
        let full = self.tile_path(path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Write atomically: write to temp file, then rename
        let tmp = full.with_extension("tmp");
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, &full)?;
        Ok(())
    }

    fn get_tile(&self, path: &str) -> io::Result<Vec<u8>> {
        std::fs::read(self.tile_path(path))
    }

    fn tile_exists(&self, path: &str) -> bool {
        self.tile_path(path).exists()
    }
}

impl CheckpointStore for LocalStore {
    fn get(&self) -> io::Result<Option<String>> {
        match std::fs::read_to_string(self.checkpoint_path()) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn compare_and_swap(&self, expected: Option<&str>, new: &str) -> io::Result<bool> {
        let current = self.get()?;
        if current.as_deref() != expected {
            return Ok(false);
        }
        // Atomic write
        let tmp = self.checkpoint_path().with_extension("tmp");
        std::fs::write(&tmp, new)?;
        std::fs::rename(&tmp, &self.checkpoint_path())?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_store_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path()).unwrap();

        // Tiles
        assert!(!store.tile_exists("tile/0/000"));
        store.put_tile("tile/0/000", b"hello").unwrap();
        assert!(store.tile_exists("tile/0/000"));
        assert_eq!(store.get_tile("tile/0/000").unwrap(), b"hello");

        // Checkpoint CAS
        assert_eq!(store.get().unwrap(), None);
        assert!(store.compare_and_swap(None, "ckpt1").unwrap());
        assert_eq!(store.get().unwrap().as_deref(), Some("ckpt1"));
        assert!(!store.compare_and_swap(Some("wrong"), "ckpt2").unwrap());
        assert!(store.compare_and_swap(Some("ckpt1"), "ckpt2").unwrap());
        assert_eq!(store.get().unwrap().as_deref(), Some("ckpt2"));
    }
}
