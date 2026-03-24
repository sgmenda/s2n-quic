// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cosigner signature generation and verification.
//!
//! Implements the MTCSubtreeSignatureInput format from
//! draft-ietf-plants-merkle-tree-certs Section 5.4.1.

use crate::tree::{TreeHash, HASH_SIZE};
use aws_lc_rs::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use aws_lc_rs::unstable::signature::{PqdsaKeyPair, ML_DSA_87, ML_DSA_87_SIGNING};

/// The fixed label for domain separation: "mtc-subtree/v1\n\0"
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-5.4.1
//# a fixed prefix for domain separation.  Its value MUST be the string
//# mtc-subtree/v1, followed by a newline (U+000A), followed by a zero
//# byte (U+0000).
const LABEL: &[u8; 16] = b"mtc-subtree/v1\n\0";

/// Build the MTCSubtreeSignatureInput bytes.
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-5.4.1
//# log_id MUST be the issuance log's ID (Section 5.2), in its binary
//# representation (Section 3 of [I-D.ietf-tls-trust-anchor-ids]).
//
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-5.4.1
//# start
//# and end MUST define a valid subtree of the log, and hash MUST be the
//# subtree's hash value in the cosigner's view of the log.
//
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-5.4.1
//# cosigner_id MUST be the cosigner ID, in its binary
//# representation.
pub fn build_signature_input(
    cosigner_id: &[u8],
    log_id: &[u8],
    start: u64,
    end: u64,
    hash: &TreeHash,
) -> Vec<u8> {
    let mut buf = Vec::new();
    // label
    buf.extend_from_slice(LABEL);
    //= specs/merkle-tree-certs/draft-ietf-tls-trust-anchor-ids.txt#section-3
    //# For use in binary protocols such as TLS, a trust anchor ID's
    //# binary representation consists of the contents octets of the
    //# relative object identifier's DER encoding, as described in
    //# Section 8.20 of [X690].
    //
    //= specs/merkle-tree-certs/draft-ietf-tls-trust-anchor-ids.txt#section-3
    //# The length of a trust anchor ID's binary representation MUST NOT
    //# exceed 255 bytes.
    // cosigner_id: TrustAnchorID<1..2^8-1> (u8 length-prefixed)
    buf.push(cosigner_id.len() as u8);
    buf.extend_from_slice(cosigner_id);
    // MTCSubtree.log_id: TrustAnchorID<1..2^8-1>
    buf.push(log_id.len() as u8);
    buf.extend_from_slice(log_id);
    // MTCSubtree.start
    buf.extend_from_slice(&start.to_be_bytes());
    // MTCSubtree.end
    buf.extend_from_slice(&end.to_be_bytes());
    // MTCSubtree.hash
    buf.extend_from_slice(hash);
    buf
}

/// An Ed25519 cosigner that can sign subtree hashes.
pub struct Cosigner {
    key_pair: Ed25519KeyPair,
    cosigner_id: Vec<u8>,
}

impl Cosigner {
    /// Create a cosigner from a PKCS#8 Ed25519 private key and cosigner ID.
    pub fn from_pkcs8(pkcs8: &[u8], cosigner_id: &[u8]) -> Self {
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8).expect("invalid Ed25519 PKCS#8 key");
        Self {
            key_pair,
            cosigner_id: cosigner_id.to_vec(),
        }
    }

    /// Generate a new random cosigner for testing.
    pub fn generate(cosigner_id: &[u8]) -> Self {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen failed");
        Self::from_pkcs8(pkcs8.as_ref(), cosigner_id)
    }

    pub fn cosigner_id(&self) -> &[u8] {
        &self.cosigner_id
    }

    pub fn public_key(&self) -> &[u8] {
        self.key_pair.public_key().as_ref()
    }

    /// Sign a subtree hash, producing an Ed25519 signature.
    pub fn sign_subtree(
        &self,
        log_id: &[u8],
        start: u64,
        end: u64,
        hash: &TreeHash,
    ) -> Vec<u8> {
        let input = build_signature_input(&self.cosigner_id, log_id, start, end, hash);
        self.key_pair.sign(&input).as_ref().to_vec()
    }
}

/// Verify an Ed25519 cosignature on a subtree.
pub fn verify_cosignature(
    public_key: &[u8],
    cosigner_id: &[u8],
    log_id: &[u8],
    start: u64,
    end: u64,
    hash: &TreeHash,
    signature: &[u8],
) -> bool {
    let input = build_signature_input(cosigner_id, log_id, start, end, hash);
    let key = UnparsedPublicKey::new(&ED25519, public_key);
    key.verify(&input, signature).is_ok()
}

/// An ML-DSA-87 cosigner that can sign subtree hashes.
pub struct MlDsaCosigner {
    key_pair: PqdsaKeyPair,
    cosigner_id: Vec<u8>,
}

impl MlDsaCosigner {
    /// Generate a new random ML-DSA-87 cosigner.
    pub fn generate(cosigner_id: &[u8]) -> Self {
        let key_pair = PqdsaKeyPair::generate(&ML_DSA_87_SIGNING).expect("keygen failed");
        Self {
            key_pair,
            cosigner_id: cosigner_id.to_vec(),
        }
    }

    /// Generate from a deterministic 32-byte seed (for reproducible demos).
    pub fn from_seed(cosigner_id: &[u8], seed: &[u8; 32]) -> Self {
        let key_pair = PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, seed).expect("invalid seed");
        Self {
            key_pair,
            cosigner_id: cosigner_id.to_vec(),
        }
    }

    pub fn cosigner_id(&self) -> &[u8] {
        &self.cosigner_id
    }

    pub fn public_key(&self) -> &[u8] {
        self.key_pair.public_key().as_ref()
    }

    /// Sign a subtree hash, producing an ML-DSA-87 signature (4627 bytes).
    pub fn sign_subtree(&self, log_id: &[u8], start: u64, end: u64, hash: &TreeHash) -> Vec<u8> {
        let input = build_signature_input(&self.cosigner_id, log_id, start, end, hash);
        let mut sig = vec![0u8; ML_DSA_87_SIGNING.signature_len()];
        let len = self.key_pair.sign(&input, &mut sig).expect("sign failed");
        sig.truncate(len);
        sig
    }
}

/// Verify an ML-DSA-87 cosignature on a subtree.
pub fn verify_ml_dsa_cosignature(
    public_key: &[u8],
    cosigner_id: &[u8],
    log_id: &[u8],
    start: u64,
    end: u64,
    hash: &TreeHash,
    signature: &[u8],
) -> bool {
    let input = build_signature_input(cosigner_id, log_id, start, end, hash);
    let key = UnparsedPublicKey::new(&ML_DSA_87, public_key);
    key.verify(&input, signature).is_ok()
}

/// Encode cosignatures into the MTCProof signatures field.
///
/// Each signature entry is: `u8-length-prefixed cosigner_id || u16-length-prefixed signature`
pub fn encode_cosignatures(cosignatures: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    for (cosigner_id, sig) in cosignatures {
        //= specs/merkle-tree-certs/draft-ietf-tls-trust-anchor-ids.txt#section-4.1
        //# opaque TrustAnchorID<1..2^8-1>;
        buf.push(cosigner_id.len() as u8);
        buf.extend_from_slice(cosigner_id);
        // signature: u16 length-prefixed
        buf.extend_from_slice(&(sig.len() as u16).to_be_bytes());
        buf.extend_from_slice(sig);
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MerkleTreeBuilder, Subtree};

    #[test]
    fn sign_and_verify() {
        let cosigner = Cosigner::generate(b"test-cosigner");
        let log_id = b"32473.1";
        let hash = [0xab; HASH_SIZE];

        let sig = cosigner.sign_subtree(log_id, 0, 16, &hash);
        assert!(verify_cosignature(
            cosigner.public_key(),
            b"test-cosigner",
            log_id,
            0,
            16,
            &hash,
            &sig,
        ));

        // Wrong hash should fail
        let wrong_hash = [0xcd; HASH_SIZE];
        assert!(!verify_cosignature(
            cosigner.public_key(),
            b"test-cosigner",
            log_id,
            0,
            16,
            &wrong_hash,
            &sig,
        ));

        // Wrong cosigner_id should fail
        assert!(!verify_cosignature(
            cosigner.public_key(),
            b"wrong-cosigner",
            log_id,
            0,
            16,
            &hash,
            &sig,
        ));
    }

    #[test]
    fn cosign_real_subtree() {
        let mut tree = MerkleTreeBuilder::new();
        for i in 0..8u8 {
            tree.append(&[i]);
        }

        let subtree = Subtree::new(0, 8);
        let hash = tree.subtree_hash(&subtree);

        let cosigner = Cosigner::generate(b"my-cosigner");
        let log_id = b"32473.1";
        let sig = cosigner.sign_subtree(log_id, 0, 8, &hash);

        assert!(verify_cosignature(
            cosigner.public_key(),
            b"my-cosigner",
            log_id,
            0,
            8,
            &hash,
            &sig,
        ));
    }

    #[test]
    fn ml_dsa_87_sign_and_verify() {
        let cosigner = MlDsaCosigner::generate(b"pq-cosigner");
        let log_id = b"32473.1";
        let hash = [0xab; HASH_SIZE];

        let sig = cosigner.sign_subtree(log_id, 0, 16, &hash);
        assert_eq!(sig.len(), 4627, "ML-DSA-87 signature should be 4627 bytes");

        assert!(verify_ml_dsa_cosignature(
            cosigner.public_key(), b"pq-cosigner", log_id, 0, 16, &hash, &sig,
        ));

        // Wrong hash should fail
        let wrong_hash = [0xcd; HASH_SIZE];
        assert!(!verify_ml_dsa_cosignature(
            cosigner.public_key(), b"pq-cosigner", log_id, 0, 16, &wrong_hash, &sig,
        ));
    }

    #[test]
    fn ml_dsa_87_deterministic_from_seed() {
        let seed = [42u8; 32];
        let c1 = MlDsaCosigner::from_seed(b"seeded", &seed);
        let c2 = MlDsaCosigner::from_seed(b"seeded", &seed);
        assert_eq!(c1.public_key(), c2.public_key());
    }
}
