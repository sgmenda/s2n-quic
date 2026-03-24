// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checkpoint format per https://c2sp.org/tlog-checkpoint
//!
//! A checkpoint is a signed note with:
//!   Line 1: origin (log identity)
//!   Line 2: tree size (decimal)
//!   Line 3: root hash (base64)
//!   Blank line
//!   Signature lines

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use base64::Engine;

use crate::tree::TreeHash;

/// Build the checkpoint body (unsigned).
//= specs/merkle-tree-certs/tlog-checkpoint.md#note-text
//# The origin MUST be non-empty, and it SHOULD be
//# a schema-less URL containing neither Unicode spaces nor plus (U+002B), such
//# as `example.com/log42`.
pub fn checkpoint_body(origin: &str, tree_size: u64, root_hash: &TreeHash) -> String {
    let hash_b64 = base64::engine::general_purpose::STANDARD.encode(root_hash);
    format!("{origin}\n{tree_size}\n{hash_b64}\n")
}

/// Sign a checkpoint body with Ed25519, producing the full signed note.
///
/// The signed note format is:
///   <body>\n— <key_name> <base64(signature)>\n
///
/// The signature is over: "signed note: " || body
//= specs/merkle-tree-certs/tlog-tiles.md#checkpoints
//# The Signed Tree Head MUST be served as a [checkpoint][] at
//
//= specs/merkle-tree-certs/tlog-tiles.md#checkpoints
//# If the log is public, or is interacting in any way with the public witness
//# network, the checkpoint MUST carry at least one Ed25519 signature by the log.
pub fn sign_checkpoint(body: &str, key_name: &str, key_pair: &Ed25519KeyPair) -> String {
    // Signed note signature is over "signed note: " || body
    let mut msg = Vec::new();
    msg.extend_from_slice(b"signed note: ");
    msg.extend_from_slice(body.as_bytes());

    let sig = key_pair.sign(&msg);

    // The signature line includes a 4-byte key hash + the signature
    // Key hash = first 4 bytes of SHA-256(key_name || "\n" || public_key)
    let key_hash = compute_key_hash(key_name, key_pair.public_key().as_ref());

    let mut sig_bytes = Vec::new();
    sig_bytes.push(0x04); // algorithm: Ed25519 = 0x04 (from signed-note spec)
    sig_bytes.extend_from_slice(&key_hash);
    sig_bytes.extend_from_slice(sig.as_ref());

    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);
    format!("{body}\n\u{2014} {key_name} {sig_b64}\n")
}

fn compute_key_hash(key_name: &str, public_key: &[u8]) -> [u8; 4] {
    use aws_lc_rs::digest;
    let mut data = Vec::new();
    data.extend_from_slice(key_name.as_bytes());
    data.push(b'\n');
    data.push(0x04); // Ed25519 algorithm byte
    data.extend_from_slice(public_key);
    let hash = digest::digest(&digest::SHA256, &data);
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash.as_ref()[..4]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_body_format() {
        let hash = [0xab; 32];
        let body = checkpoint_body("twig.sgmenda.people.aws.dev", 42, &hash);
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines[0], "twig.sgmenda.people.aws.dev");
        assert_eq!(lines[1], "42");
        // Line 3 is base64 of the hash
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn sign_and_format() {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let hash = [0xcd; 32];
        let body = checkpoint_body("twig.sgmenda.people.aws.dev", 100, &hash);
        let signed = sign_checkpoint(&body, "twig.sgmenda.people.aws.dev", &kp);

        // Should contain the body + a signature line starting with "— "
        assert!(signed.contains("\n\u{2014} twig.sgmenda.people.aws.dev "));
        assert!(signed.starts_with("twig.sgmenda.people.aws.dev\n100\n"));
    }
}
