// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! MTC trust anchor configuration and certificate verification.
//!
//! A trust anchor holds the configuration needed to verify MTC certificates
//! from a particular issuance log: the log ID, trusted cosigner public keys,
//! and optionally predistributed trusted subtree hashes (for landmark certs).

use crate::cosigner::{verify_cosignature, verify_ml_dsa_cosignature};
use crate::entry::{read_tlv, read_tlv_raw};
use crate::tree::{evaluate_inclusion_proof, hash_leaf, TreeHash, HASH_SIZE};
use crate::Subtree;
use aws_lc_rs::digest;

/// Signature algorithm for a trusted cosigner.
#[derive(Clone, Copy)]
pub enum CosignerAlgorithm {
    Ed25519,
    MlDsa87,
}

/// A trusted cosigner's public key and ID.
pub struct TrustedCosigner {
    pub cosigner_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub algorithm: CosignerAlgorithm,
}

/// Configuration for verifying MTC certificates from a single issuance log.
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-7.4
//# As an optional optimization, a relying party MAY incorporate a
//# periodically updated, predistributed list of active landmark
//# subtrees, determined as described in Section 6.3.1.
//
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-7.3
//# In picking trusted cosigners, the relying party SHOULD ensure the
//# following security properties:
//
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-7.3
//# Relying parties SHOULD ensure authenticity by requiring a signature
//# from the most recent CA cosigner key.
pub struct TrustAnchor {
    pub log_id: Vec<u8>,
    pub cosigners: Vec<TrustedCosigner>,
    /// Minimum number of cosigner signatures required.
    //= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-7.3
    //# To mitigate this, relying parties SHOULD ensure transparency by
    //# requiring a quorum of signatures from additional cosigners.
    pub quorum: usize,
    /// Predistributed trusted subtree hashes (for landmark certs).
    //= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-7.4
    //# Before configuring the subtrees as trusted, the relying party MUST
    //# obtain assurance that each subtree is consistent with checkpoints
    //# observed by a sufficient set of cosigners (see Section 5.4) to meet
    //# its cosigner requirements.
    pub trusted_subtrees: Vec<(Subtree, TreeHash)>,
}

impl TrustAnchor {
    /// Look up a trusted subtree hash by exact range match.
    pub fn trusted_subtree_hash(&self, subtree: &Subtree) -> Option<&TreeHash> {
        self.trusted_subtrees
            .iter()
            .find(|(s, _)| s == subtree)
            .map(|(_, h)| h)
    }
}

/// Result of verifying an MTC certificate.
#[derive(Debug)]
pub enum VerifyError {
    /// Signature algorithm is not id-alg-mtcProof.
    NotMtcCert,
    /// Could not parse the MTCProof from signatureValue.
    MalformedProof,
    /// Could not parse the TBSCertificate.
    MalformedTbs,
    /// The subtree range is not valid.
    InvalidSubtree,
    /// Inclusion proof evaluation failed.
    InclusionProofFailed,
    /// No trusted subtree matched and cosignature verification failed.
    UntrustedSubtree,
    /// Insufficient cosigner signatures.
    InsufficientCosignatures,
}

/// OID for id-alg-mtcProof (experimental): 1.3.6.1.4.1.44363.47.0
const OID_MTC_PROOF: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xda, 0x4b, 0x2f, 0x00];

//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-7.2
//# Unrecognized cosigners MUST be ignored.
//
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-7.2
//# The relying party MUST continue to perform
//# other checks, such as checking expiry.

/// Verify an MTC certificate (DER-encoded) against a trust anchor.
///
/// This implements the verification procedure from spec section 7.2.
/// The caller is responsible for additional checks (expiry, name constraints, etc).
pub fn verify_mtc_cert(cert_der: &[u8], anchor: &TrustAnchor) -> Result<(), VerifyError> {
    // Parse the Certificate SEQUENCE
    let (cert_content, _) = read_tlv(cert_der);
    let mut cursor = cert_content;

    // TBSCertificate
    let (_, tbs_len) = read_tlv_raw(cursor);
    let tbs_der = &cursor[..tbs_len];
    cursor = &cursor[tbs_len..];

    // signatureAlgorithm — check it's mtcProof
    let (sig_alg_content, sig_alg_len) = read_tlv(cursor);
    let (oid_bytes, _) = read_tlv(sig_alg_content);
    if oid_bytes != OID_MTC_PROOF {
        return Err(VerifyError::NotMtcCert);
    }
    cursor = &cursor[sig_alg_len..];

    // signatureValue BIT STRING
    let (sig_bits, _) = read_tlv(cursor);
    if sig_bits.is_empty() || sig_bits[0] != 0 {
        return Err(VerifyError::MalformedProof);
    }
    let mtc_proof_bytes = &sig_bits[1..]; // skip unused-bits byte

    // Parse MTCProof: start(u64) || end(u64) || u16-len proof || u16-len signatures
    if mtc_proof_bytes.len() < 20 {
        return Err(VerifyError::MalformedProof);
    }
    let start = u64::from_be_bytes(mtc_proof_bytes[0..8].try_into().unwrap());
    let end = u64::from_be_bytes(mtc_proof_bytes[8..16].try_into().unwrap());
    let proof_len = u16::from_be_bytes(mtc_proof_bytes[16..18].try_into().unwrap()) as usize;
    if mtc_proof_bytes.len() < 18 + proof_len + 2 {
        return Err(VerifyError::MalformedProof);
    }
    let inclusion_proof = &mtc_proof_bytes[18..18 + proof_len];
    let sigs_offset = 18 + proof_len;
    let sigs_len =
        u16::from_be_bytes(mtc_proof_bytes[sigs_offset..sigs_offset + 2].try_into().unwrap())
            as usize;
    let signatures_bytes = &mtc_proof_bytes[sigs_offset + 2..sigs_offset + 2 + sigs_len];

    // Extract serial number (index) from TBSCertificate
    let (tbs_content, _) = read_tlv(tbs_der);
    let mut tbs_cursor = tbs_content;

    // Skip version [0] if present
    if !tbs_cursor.is_empty() && tbs_cursor[0] == 0xa0 {
        let (_, vlen) = read_tlv_raw(tbs_cursor);
        tbs_cursor = &tbs_cursor[vlen..];
    }
    // serialNumber INTEGER
    let (serial_content, serial_len) = read_tlv(tbs_cursor);
    let mut index: u64 = 0;
    for b in serial_content {
        index = (index << 8) | (*b as u64);
    }
    tbs_cursor = &tbs_cursor[serial_len..];

    // Compute entry_hash from TBSCertificate (plants-02 format)
    let entry_hash = compute_entry_hash_from_tbs(tbs_der).ok_or(VerifyError::MalformedTbs)?;

    // Evaluate inclusion proof
    let subtree = Subtree::new(start, end);
    if !subtree.is_valid() {
        return Err(VerifyError::InvalidSubtree);
    }

    let expected_subtree_hash =
        evaluate_inclusion_proof(inclusion_proof, index, &entry_hash, &subtree)
            .ok_or(VerifyError::InclusionProofFailed)?;

    // Step 7: Check trusted subtrees (landmark path)
    if let Some(trusted_hash) = anchor.trusted_subtree_hash(&subtree) {
        if expected_subtree_hash == *trusted_hash {
            return Ok(());
        }
        return Err(VerifyError::UntrustedSubtree);
    }

    // Step 8: Verify cosignatures (standalone path)
    let mut valid_cosigs = 0usize;
    let mut sig_cursor = signatures_bytes;
    while !sig_cursor.is_empty() {
        //= specs/merkle-tree-certs/draft-ietf-tls-trust-anchor-ids.txt#section-4.1
        //# opaque TrustAnchorID<1..2^8-1>;
        let id_len = sig_cursor[0] as usize;
        sig_cursor = &sig_cursor[1..];
        let cosigner_id = &sig_cursor[..id_len];
        sig_cursor = &sig_cursor[id_len..];
        // signature: u16 length-prefixed
        let sig_len = u16::from_be_bytes(sig_cursor[..2].try_into().unwrap()) as usize;
        sig_cursor = &sig_cursor[2..];
        let signature = &sig_cursor[..sig_len];
        sig_cursor = &sig_cursor[sig_len..];

        // Find matching trusted cosigner (unrecognized cosigners are ignored)
        for tc in &anchor.cosigners {
            if tc.cosigner_id == cosigner_id {
                let verified = match tc.algorithm {
                    CosignerAlgorithm::Ed25519 => verify_cosignature(
                        &tc.public_key, cosigner_id, &anchor.log_id,
                        start, end, &expected_subtree_hash, signature,
                    ),
                    CosignerAlgorithm::MlDsa87 => verify_ml_dsa_cosignature(
                        &tc.public_key, cosigner_id, &anchor.log_id,
                        start, end, &expected_subtree_hash, signature,
                    ),
                };
                if verified {
                    valid_cosigs += 1;
                    break;
                }
            }
        }
    }

    if valid_cosigs >= anchor.quorum {
        Ok(())
    } else {
        Err(VerifyError::InsufficientCosignatures)
    }
}

/// Compute entry_hash from a DER TBSCertificate (plants-02 format).
fn compute_entry_hash_from_tbs(tbs_der: &[u8]) -> Option<TreeHash> {
    let (tbs_content, _) = read_tlv(tbs_der);
    let mut cursor = tbs_content;

    // version [0] EXPLICIT (optional)
    let version_bytes;
    if cursor[0] == 0xa0 {
        let (_, consumed) = read_tlv_raw(cursor);
        version_bytes = &cursor[..consumed];
        cursor = &cursor[consumed..];
    } else {
        version_bytes = &[];
    }

    // serialNumber — skip
    let (_, consumed) = read_tlv_raw(cursor);
    cursor = &cursor[consumed..];

    // signature AlgorithmIdentifier — skip
    let (_, consumed) = read_tlv_raw(cursor);
    cursor = &cursor[consumed..];

    // issuer
    let (_, consumed) = read_tlv_raw(cursor);
    let issuer_bytes = &cursor[..consumed];
    cursor = &cursor[consumed..];

    // validity
    let (_, consumed) = read_tlv_raw(cursor);
    let validity_bytes = &cursor[..consumed];
    cursor = &cursor[consumed..];

    // subject
    let (_, consumed) = read_tlv_raw(cursor);
    let subject_bytes = &cursor[..consumed];
    cursor = &cursor[consumed..];

    // subjectPublicKeyInfo
    let (_, spki_consumed) = read_tlv_raw(cursor);
    let spki_bytes = &cursor[..spki_consumed];
    let (spki_content, _) = read_tlv(spki_bytes);
    let (_, alg_consumed) = read_tlv_raw(spki_content);
    let spki_alg_bytes = &spki_content[..alg_consumed];
    cursor = &cursor[spki_consumed..];

    let spki_hash = digest::digest(&digest::SHA256, spki_bytes);
    let after_spki = cursor;

    let mut entry = Vec::new();
    entry.extend_from_slice(&[0x00, 0x01]);
    entry.extend_from_slice(version_bytes);
    entry.extend_from_slice(issuer_bytes);
    entry.extend_from_slice(validity_bytes);
    entry.extend_from_slice(subject_bytes);
    entry.extend_from_slice(spki_alg_bytes);
    entry.push(0x04);
    entry.push(HASH_SIZE as u8);
    entry.extend_from_slice(spki_hash.as_ref());
    entry.extend_from_slice(after_spki);

    Some(hash_leaf(&entry))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_entry, build_mtc_cert, build_mtc_proof, Cosigner, MerkleTreeBuilder};

    fn sample_validity() -> Vec<u8> {
        let nb = &[0x17, 0x0d, b'2', b'0', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z'];
        let na = &[0x17, 0x0d, b'3', b'0', b'1', b'2', b'3', b'1', b'2', b'3', b'5', b'9', b'5', b'9', b'Z'];
        let mut v = vec![0x30, (nb.len() + na.len()) as u8];
        v.extend_from_slice(nb);
        v.extend_from_slice(na);
        v
    }

    fn sample_subject() -> Vec<u8> {
        let oid = &[0x06, 0x03, 0x55, 0x04, 0x03];
        let val = &[0x0c, 0x04, b't', b'e', b's', b't'];
        let attr = [0x30, (oid.len() + val.len()) as u8].iter().chain(oid.iter()).chain(val.iter()).copied().collect::<Vec<_>>();
        let rdn = [0x31, attr.len() as u8].iter().chain(attr.iter()).copied().collect::<Vec<_>>();
        [0x30, rdn.len() as u8].iter().chain(rdn.iter()).copied().collect()
    }

    fn issuer_name(log_id: &str) -> Vec<u8> {
        let oid = &[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xda, 0x4b, 0x2f, 0x01];
        let val = {
            let mut v = vec![0x0c, log_id.len() as u8];
            v.extend_from_slice(log_id.as_bytes());
            v
        };
        let inner: Vec<u8> = [oid.to_vec(), val].concat();
        let attr = [vec![0x30, inner.len() as u8], inner].concat();
        let rdn = [vec![0x31, attr.len() as u8], attr].concat();
        [vec![0x30, rdn.len() as u8], rdn].concat()
    }

    const V3: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x02];
    const SPKI: &[u8] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00, 0x04, 0xcb, 0x18, 0x82, 0xd7, 0xa9, 0x6d, 0xb3, 0xe4, 0x8e,
        0x2f, 0xce, 0xce, 0xc0, 0x78, 0x46, 0x0f, 0x32, 0xbd, 0xfd, 0xdc, 0x94,
        0x77, 0xbb, 0x0c, 0xf3, 0x48, 0xc0, 0x7f, 0x9d, 0xd5, 0x2f, 0xe0, 0x15,
        0xdf, 0xc1, 0xe8, 0x1c, 0xaa, 0x66, 0x03, 0xb2, 0xc9, 0xa1, 0x82, 0xdf,
        0xe3, 0x25, 0x61, 0x71, 0x59, 0x5e, 0x35, 0xcc, 0x6e, 0x7e, 0xc0, 0x1f,
        0x70, 0xfb, 0x9e, 0x4c, 0xb5, 0xf4, 0x56,
    ];

    #[test]
    fn verify_landmark_cert() {
        let log_id = "32473.1";
        let validity = sample_validity();
        let subject = sample_subject();
        let issuer = issuer_name(log_id);

        let mut tree = MerkleTreeBuilder::new();
        tree.append(&[0x00, 0x00]);
        let (_, entry_hash) = build_entry(V3, &issuer, &validity, &subject, SPKI, &[]);
        tree.append_hash(entry_hash);

        let subtree = Subtree::new(0, 2);
        let subtree_hash = tree.subtree_hash(&subtree);
        let proof = tree.inclusion_proof(1, &subtree);
        let mtc_proof = build_mtc_proof(0, 2, &proof);
        let cert = build_mtc_cert(1, log_id, V3, &validity, &subject, SPKI, &[], &mtc_proof);

        let anchor = TrustAnchor {
            log_id: log_id.as_bytes().to_vec(),
            cosigners: vec![],
            quorum: 0,
            trusted_subtrees: vec![(subtree, subtree_hash)],
        };

        verify_mtc_cert(&cert, &anchor).expect("landmark verification failed");
    }

    #[test]
    fn verify_standalone_cert_with_cosigners() {
        let log_id = b"32473.1";
        let validity = sample_validity();
        let subject = sample_subject();
        let issuer = issuer_name("32473.1");

        let mut tree = MerkleTreeBuilder::new();
        tree.append(&[0x00, 0x00]);
        let (_, entry_hash) = build_entry(V3, &issuer, &validity, &subject, SPKI, &[]);
        tree.append_hash(entry_hash);

        let subtree = Subtree::new(0, 2);
        let subtree_hash = tree.subtree_hash(&subtree);

        // Create cosigners and sign
        let c1 = Cosigner::generate(b"cosigner-1");
        let c2 = Cosigner::generate(b"cosigner-2");
        let sig1 = c1.sign_subtree(log_id, 0, 2, &subtree_hash);
        let sig2 = c2.sign_subtree(log_id, 0, 2, &subtree_hash);

        // Build MTCProof with cosignatures
        let proof = tree.inclusion_proof(1, &subtree);
        let cosigs = crate::encode_cosignatures(&[
            (b"cosigner-1" as &[u8], &sig1),
            (b"cosigner-2" as &[u8], &sig2),
        ]);
        let mut mtc_proof_bytes = Vec::new();
        mtc_proof_bytes.extend_from_slice(&0u64.to_be_bytes());
        mtc_proof_bytes.extend_from_slice(&2u64.to_be_bytes());
        mtc_proof_bytes.extend_from_slice(&(proof.len() as u16).to_be_bytes());
        mtc_proof_bytes.extend_from_slice(&proof);
        mtc_proof_bytes.extend_from_slice(&(cosigs.len() as u16).to_be_bytes());
        mtc_proof_bytes.extend_from_slice(&cosigs);

        let cert = build_mtc_cert(1, "32473.1", V3, &validity, &subject, SPKI, &[], &mtc_proof_bytes);

        // Verify with quorum=2
        let anchor = TrustAnchor {
            log_id: log_id.to_vec(),
            cosigners: vec![
                TrustedCosigner { cosigner_id: b"cosigner-1".to_vec(), public_key: c1.public_key().to_vec(), algorithm: CosignerAlgorithm::Ed25519 },
                TrustedCosigner { cosigner_id: b"cosigner-2".to_vec(), public_key: c2.public_key().to_vec(), algorithm: CosignerAlgorithm::Ed25519 },
            ],
            quorum: 2,
            trusted_subtrees: vec![],
        };

        verify_mtc_cert(&cert, &anchor).expect("standalone verification failed");
    }

    #[test]
    fn verify_fails_insufficient_quorum() {
        let log_id = b"32473.1";
        let validity = sample_validity();
        let subject = sample_subject();
        let issuer = issuer_name("32473.1");

        let mut tree = MerkleTreeBuilder::new();
        tree.append(&[0x00, 0x00]);
        let (_, entry_hash) = build_entry(V3, &issuer, &validity, &subject, SPKI, &[]);
        tree.append_hash(entry_hash);

        let subtree = Subtree::new(0, 2);
        let subtree_hash = tree.subtree_hash(&subtree);

        let c1 = Cosigner::generate(b"cosigner-1");
        let sig1 = c1.sign_subtree(log_id, 0, 2, &subtree_hash);

        let proof = tree.inclusion_proof(1, &subtree);
        let cosigs = crate::encode_cosignatures(&[(b"cosigner-1" as &[u8], &sig1)]);
        let mut mtc_proof_bytes = Vec::new();
        mtc_proof_bytes.extend_from_slice(&0u64.to_be_bytes());
        mtc_proof_bytes.extend_from_slice(&2u64.to_be_bytes());
        mtc_proof_bytes.extend_from_slice(&(proof.len() as u16).to_be_bytes());
        mtc_proof_bytes.extend_from_slice(&proof);
        mtc_proof_bytes.extend_from_slice(&(cosigs.len() as u16).to_be_bytes());
        mtc_proof_bytes.extend_from_slice(&cosigs);

        let cert = build_mtc_cert(1, "32473.1", V3, &validity, &subject, SPKI, &[], &mtc_proof_bytes);

        // Require quorum=2 but only 1 cosigner signed
        let anchor = TrustAnchor {
            log_id: log_id.to_vec(),
            cosigners: vec![
                TrustedCosigner { cosigner_id: b"cosigner-1".to_vec(), public_key: c1.public_key().to_vec(), algorithm: CosignerAlgorithm::Ed25519 },
            ],
            quorum: 2,
            trusted_subtrees: vec![],
        };

        assert!(matches!(verify_mtc_cert(&cert, &anchor), Err(VerifyError::InsufficientCosignatures)));
    }

    #[test]
    fn verify_standalone_cert_with_ml_dsa_87() {
        use crate::cosigner::MlDsaCosigner;

        let log_id = b"32473.1";
        let validity = sample_validity();
        let subject = sample_subject();
        let issuer = issuer_name("32473.1");

        let mut tree = MerkleTreeBuilder::new();
        tree.append(&[0x00, 0x00]); // null entry at index 0
        let (_, entry_hash) = build_entry(V3, &issuer, &validity, &subject, SPKI, &[]);
        tree.append_hash(entry_hash);

        let subtree = Subtree::new(0, 2);
        let subtree_hash = tree.subtree_hash(&subtree);

        let c1 = MlDsaCosigner::generate(b"pq-cosigner-1");
        let sig1 = c1.sign_subtree(log_id, 0, 2, &subtree_hash);

        let proof = tree.inclusion_proof(1, &subtree);
        let cosigs = crate::encode_cosignatures(&[(b"pq-cosigner-1" as &[u8], &sig1)]);
        let mut mtc_proof_bytes = Vec::new();
        mtc_proof_bytes.extend_from_slice(&0u64.to_be_bytes());
        mtc_proof_bytes.extend_from_slice(&2u64.to_be_bytes());
        mtc_proof_bytes.extend_from_slice(&(proof.len() as u16).to_be_bytes());
        mtc_proof_bytes.extend_from_slice(&proof);
        mtc_proof_bytes.extend_from_slice(&(cosigs.len() as u16).to_be_bytes());
        mtc_proof_bytes.extend_from_slice(&cosigs);

        let cert = build_mtc_cert(1, "32473.1", V3, &validity, &subject, SPKI, &[], &mtc_proof_bytes);

        let anchor = TrustAnchor {
            log_id: log_id.to_vec(),
            cosigners: vec![
                TrustedCosigner {
                    cosigner_id: b"pq-cosigner-1".to_vec(),
                    public_key: c1.public_key().to_vec(),
                    algorithm: CosignerAlgorithm::MlDsa87,
                },
            ],
            quorum: 1,
            trusted_subtrees: vec![],
        };

        assert!(verify_mtc_cert(&cert, &anchor).is_ok());

        // The ML-DSA-87 cosignature is 4627 bytes, but the cert is much smaller
        // than a traditional cert with an ML-DSA-87 signature would be
        eprintln!("ML-DSA-87 cosignature size: {} bytes", sig1.len());
        eprintln!("MTC cert size: {} bytes", cert.len());
    }

    #[test]
    fn verify_standalone_cert_mixed_ed25519_and_ml_dsa_87() {
        use crate::cosigner::MlDsaCosigner;

        let log_id = b"32473.1";
        let validity = sample_validity();
        let subject = sample_subject();
        let issuer = issuer_name("32473.1");

        let mut tree = MerkleTreeBuilder::new();
        tree.append(&[0x00, 0x00]);
        let (_, entry_hash) = build_entry(V3, &issuer, &validity, &subject, SPKI, &[]);
        tree.append_hash(entry_hash);

        let subtree = Subtree::new(0, 2);
        let subtree_hash = tree.subtree_hash(&subtree);

        let ed = Cosigner::generate(b"ed-cosigner");
        let pq = MlDsaCosigner::generate(b"pq-cosigner");
        let sig_ed = ed.sign_subtree(log_id, 0, 2, &subtree_hash);
        let sig_pq = pq.sign_subtree(log_id, 0, 2, &subtree_hash);

        let proof = tree.inclusion_proof(1, &subtree);
        let cosigs = crate::encode_cosignatures(&[
            (b"ed-cosigner" as &[u8], &sig_ed),
            (b"pq-cosigner" as &[u8], &sig_pq),
        ]);
        let mut mtc_proof_bytes = Vec::new();
        mtc_proof_bytes.extend_from_slice(&0u64.to_be_bytes());
        mtc_proof_bytes.extend_from_slice(&2u64.to_be_bytes());
        mtc_proof_bytes.extend_from_slice(&(proof.len() as u16).to_be_bytes());
        mtc_proof_bytes.extend_from_slice(&proof);
        mtc_proof_bytes.extend_from_slice(&(cosigs.len() as u16).to_be_bytes());
        mtc_proof_bytes.extend_from_slice(&cosigs);

        let cert = build_mtc_cert(1, "32473.1", V3, &validity, &subject, SPKI, &[], &mtc_proof_bytes);

        // Require quorum=2 with mixed algorithms
        let anchor = TrustAnchor {
            log_id: log_id.to_vec(),
            cosigners: vec![
                TrustedCosigner { cosigner_id: b"ed-cosigner".to_vec(), public_key: ed.public_key().to_vec(), algorithm: CosignerAlgorithm::Ed25519 },
                TrustedCosigner { cosigner_id: b"pq-cosigner".to_vec(), public_key: pq.public_key().to_vec(), algorithm: CosignerAlgorithm::MlDsa87 },
            ],
            quorum: 2,
            trusted_subtrees: vec![],
        };

        assert!(verify_mtc_cert(&cert, &anchor).is_ok());
    }

    #[test]
    fn verify_landmark_cert_wrong_subtree_hash() {
        let log_id = b"32473.1";
        let validity = sample_validity();
        let subject = sample_subject();
        let issuer = issuer_name("32473.1");

        let mut tree = MerkleTreeBuilder::new();
        tree.append(&[0x00, 0x00]);
        let (_, entry_hash) = build_entry(V3, &issuer, &validity, &subject, SPKI, &[]);
        tree.append_hash(entry_hash);

        let subtree = Subtree::new(0, 2);
        let proof = tree.inclusion_proof(1, &subtree);
        let mtc_proof = crate::build_mtc_proof(0, 2, &proof);
        let cert = build_mtc_cert(1, "32473.1", V3, &validity, &subject, SPKI, &[], &mtc_proof);

        let wrong_hash = [0xFFu8; HASH_SIZE];
        let anchor = TrustAnchor {
            log_id: log_id.to_vec(),
            cosigners: vec![],
            quorum: 0,
            trusted_subtrees: vec![(subtree, wrong_hash)],
        };

        assert!(matches!(verify_mtc_cert(&cert, &anchor), Err(VerifyError::UntrustedSubtree)));
    }


    #[test]
    fn verify_malformed_proof() {
        let log_id = b"32473.1";
        let validity = sample_validity();
        let subject = sample_subject();

        // Build a cert with a truncated MTCProof
        let truncated_proof = &[0u8; 10]; // too short for start+end+proof_len
        let cert = build_mtc_cert(1, "32473.1", V3, &validity, &subject, SPKI, &[], truncated_proof);

        let anchor = TrustAnchor {
            log_id: log_id.to_vec(),
            cosigners: vec![],
            quorum: 0,
            trusted_subtrees: vec![],
        };

        assert!(matches!(verify_mtc_cert(&cert, &anchor), Err(VerifyError::MalformedProof)));
    }
}
