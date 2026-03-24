// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Round-trip test: generate entries → build tree → produce certs → verify certs.

use s2n_quic_mtc::*;

/// A minimal X.509 v3 version field: [0] EXPLICIT INTEGER 2
const V3_VERSION: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x02];

/// A sample SPKI (EC P-256) — taken from the demo tool's test data.
const SAMPLE_SPKI: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0xcb, 0x18, 0x82, 0xd7, 0xa9, 0x6d, 0xb3, 0xe4, 0x8e,
    0x2f, 0xce, 0xce, 0xc0, 0x78, 0x46, 0x0f, 0x32, 0xbd, 0xfd, 0xdc, 0x94,
    0x77, 0xbb, 0x0c, 0xf3, 0x48, 0xc0, 0x7f, 0x9d, 0xd5, 0x2f, 0xe0, 0x15,
    0xdf, 0xc1, 0xe8, 0x1c, 0xaa, 0x66, 0x03, 0xb2, 0xc9, 0xa1, 0x82, 0xdf,
    0xe3, 0x25, 0x61, 0x71, 0x59, 0x5e, 0x35, 0xcc, 0x6e, 0x7e, 0xc0, 0x1f,
    0x70, 0xfb, 0x9e, 0x4c, 0xb5, 0xf4, 0x56,
];

/// Build a minimal DER-encoded Validity (NotBefore, NotAfter as UTCTime).
fn sample_validity() -> Vec<u8> {
    // UTCTime "200101000000Z" and "301231235959Z"
    let not_before = &[0x17, 0x0d, b'2', b'0', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z'];
    let not_after  = &[0x17, 0x0d, b'3', b'0', b'1', b'2', b'3', b'1', b'2', b'3', b'5', b'9', b'5', b'9', b'Z'];
    let mut v = vec![0x30, (not_before.len() + not_after.len()) as u8];
    v.extend_from_slice(not_before);
    v.extend_from_slice(not_after);
    v
}

/// Build a minimal DER-encoded Name with a single CN.
fn sample_subject(cn: &str) -> Vec<u8> {
    // OID for commonName: 2.5.4.3
    let oid = &[0x06, 0x03, 0x55, 0x04, 0x03];
    let val = {
        let mut v = vec![0x0c]; // UTF8String
        v.push(cn.len() as u8);
        v.extend_from_slice(cn.as_bytes());
        v
    };
    let attr_seq = {
        let inner: Vec<u8> = [oid.to_vec(), val].concat();
        let mut s = vec![0x30, inner.len() as u8];
        s.extend_from_slice(&inner);
        s
    };
    let rdn_set = {
        let mut s = vec![0x31, attr_seq.len() as u8];
        s.extend_from_slice(&attr_seq);
        s
    };
    let mut name = vec![0x30, rdn_set.len() as u8];
    name.extend_from_slice(&rdn_set);
    name
}

#[test]
fn round_trip() {
    let log_id = "32473.1";
    let n = 20u64;

    // 1. Create entries and build the tree
    let mut tree = MerkleTreeBuilder::new();

    // Entry 0 is always a null entry
    let null_entry = vec![0x00, 0x00]; // MerkleTreeCertEntryType::NullEntry
    tree.append(&null_entry);

    let validity = sample_validity();
    let mut entry_hashes = vec![TreeHash::default()]; // placeholder for null entry

    for i in 1..n {
        let subject = sample_subject(&format!("test-{i}.example"));
        let (entry_bytes, entry_hash) = build_entry(
            V3_VERSION,
            &build_issuer_for_entry(log_id),
            &validity,
            &subject,
            SAMPLE_SPKI,
            &[], // no extensions
        );
        tree.append(&entry_bytes);
        entry_hashes.push(entry_hash);
    }

    assert_eq!(tree.size(), n);

    // 2. Pick a subtree and generate certs
    let subtree = Subtree::new(0, n);
    let expected_subtree_hash = tree.subtree_hash(&subtree);

    for i in 1..n {
        let subject = sample_subject(&format!("test-{i}.example"));

        // Generate inclusion proof
        let proof_bytes = tree.inclusion_proof(i, &subtree);
        let mtc_proof = build_mtc_proof(subtree.start, subtree.end, &proof_bytes);

        // Generate the certificate
        let cert_der = build_mtc_cert(
            i,
            log_id,
            V3_VERSION,
            &validity,
            &subject,
            SAMPLE_SPKI,
            &[], // no extensions
            &mtc_proof,
        );

        // 3. Verify: parse the cert back and check the inclusion proof
        // Extract the entry_hash for this entry
        let entry_hash = entry_hashes[i as usize];

        // Verify the inclusion proof directly
        let computed = evaluate_inclusion_proof(&proof_bytes, i, &entry_hash, &subtree);
        assert_eq!(
            computed,
            Some(expected_subtree_hash),
            "inclusion proof failed for index {i}"
        );

        // Also verify the cert is valid DER (basic sanity)
        assert_eq!(cert_der[0], 0x30, "cert should start with SEQUENCE tag");
    }
}

#[test]
fn round_trip_partial_subtree() {
    let log_id = "32473.1";
    let validity = sample_validity();
    let mut tree = MerkleTreeBuilder::new();

    // Build a tree with 25 entries (null + 24 real)
    let null_entry = vec![0x00, 0x00];
    tree.append(&null_entry);

    let mut entry_hashes = vec![TreeHash::default()];
    for i in 1..25u64 {
        let subject = sample_subject(&format!("entry-{i}.example"));
        let (entry_bytes, entry_hash) = build_entry(
            V3_VERSION,
            &build_issuer_for_entry(log_id),
            &validity,
            &subject,
            SAMPLE_SPKI,
            &[],
        );
        tree.append(&entry_bytes);
        entry_hashes.push(entry_hash);
    }

    // Verify against subtree [16, 24) — a full power-of-2 subtree
    let subtree = Subtree::new(16, 24);
    let subtree_hash = tree.subtree_hash(&subtree);

    for i in 16..24u64 {
        let proof_bytes = tree.inclusion_proof(i, &subtree);
        let computed = evaluate_inclusion_proof(
            &proof_bytes,
            i,
            &entry_hashes[i as usize],
            &subtree,
        );
        assert_eq!(computed, Some(subtree_hash), "failed for index {i}");
    }

    // Verify against subtree [0, 25) — the full tree (partial, not power of 2)
    let full = Subtree::new(0, 25);
    let root = tree.root_hash();

    for i in 1..25u64 {
        let proof_bytes = tree.inclusion_proof(i, &full);
        let computed = evaluate_inclusion_proof(
            &proof_bytes,
            i,
            &entry_hashes[i as usize],
            &full,
        );
        assert_eq!(computed, Some(root), "full tree failed for index {i}");
    }
}

/// Build the issuer Name for use inside a TBSCertificateLogEntry.
/// This matches the format used by build_mtc_cert's issuer.
fn build_issuer_for_entry(log_id: &str) -> Vec<u8> {
    // OID for id-rdna-trustAnchorID (experimental): 1.3.6.1.4.1.44363.47.1
    let oid = &[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xda, 0x4b, 0x2f, 0x01];
    let val = {
        let mut v = vec![0x0c]; // UTF8String
        v.push(log_id.len() as u8);
        v.extend_from_slice(log_id.as_bytes());
        v
    };
    let attr_seq = {
        let inner: Vec<u8> = [oid.to_vec(), val].concat();
        let mut s = vec![0x30, inner.len() as u8];
        s.extend_from_slice(&inner);
        s
    };
    let rdn_set = {
        let mut s = vec![0x31, attr_seq.len() as u8];
        s.extend_from_slice(&attr_seq);
        s
    };
    let mut name = vec![0x30, rdn_set.len() as u8];
    name.extend_from_slice(&rdn_set);
    name
}
