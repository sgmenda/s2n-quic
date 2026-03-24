// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generate MTC certs and write them to disk for interop testing with BoringSSL.

use s2n_quic_mtc::*;
use std::io::Write;

const V3_VERSION: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x02];

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

fn sample_validity() -> Vec<u8> {
    let not_before = &[0x17, 0x0d, b'2', b'0', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z'];
    let not_after  = &[0x17, 0x0d, b'3', b'0', b'1', b'2', b'3', b'1', b'2', b'3', b'5', b'9', b'5', b'9', b'Z'];
    let mut v = vec![0x30, (not_before.len() + not_after.len()) as u8];
    v.extend_from_slice(not_before);
    v.extend_from_slice(not_after);
    v
}

fn sample_subject(cn: &str) -> Vec<u8> {
    let oid = &[0x06, 0x03, 0x55, 0x04, 0x03];
    let val = {
        let mut v = vec![0x0c];
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

fn build_issuer_for_entry(log_id: &str) -> Vec<u8> {
    let oid = &[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xda, 0x4b, 0x2f, 0x01];
    let val = {
        let mut v = vec![0x0c];
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

fn to_pem(der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// Generate certs and write them + metadata to a temp directory.
/// Prints the subtree hashes needed to configure BoringSSL's MTCAnchor.
#[test]
fn generate_interop_certs() {
    let log_id = "32473.1";
    let validity = sample_validity();
    let out_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/interop");
    std::fs::create_dir_all(&out_dir).unwrap();

    let mut tree = MerkleTreeBuilder::new();

    // Null entry at index 0
    tree.append(&[0x00, 0x00]);

    let mut entry_hashes = vec![TreeHash::default()];

    // Generate 15 real entries (indices 1-15), total tree size = 16
    for i in 1..16u64 {
        let subject = sample_subject(&format!("interop-{i}.example"));
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

    assert_eq!(tree.size(), 16);

    // Use subtree [0, 16) — the full tree
    let subtree = Subtree::new(0, 16);
    let subtree_hash = tree.subtree_hash(&subtree);

    use base64::Engine;
    let hash_b64 = base64::engine::general_purpose::STANDARD.encode(subtree_hash);

    // Write metadata
    let mut meta = std::fs::File::create(out_dir.join("metadata.txt")).unwrap();
    writeln!(meta, "log_id: {log_id}").unwrap();
    writeln!(meta, "tree_size: {}", tree.size()).unwrap();
    writeln!(meta, "subtree: [0, 16)").unwrap();
    writeln!(meta, "subtree_hash_b64: {hash_b64}").unwrap();
    writeln!(meta, "subtree_hash_hex: {}", hex::encode(subtree_hash)).unwrap();

    // Generate and write certs for entries 1-15
    for i in 1..16u64 {
        let subject = sample_subject(&format!("interop-{i}.example"));
        let proof_bytes = tree.inclusion_proof(i, &subtree);
        let mtc_proof = build_mtc_proof(subtree.start, subtree.end, &proof_bytes);
        let cert_der = build_mtc_cert(
            i,
            log_id,
            V3_VERSION,
            &validity,
            &subject,
            SAMPLE_SPKI,
            &[],
            &mtc_proof,
        );

        // Sanity: verify our own cert
        let computed = evaluate_inclusion_proof(
            &proof_bytes, i, &entry_hashes[i as usize], &subtree,
        );
        assert_eq!(computed, Some(subtree_hash));

        let pem = to_pem(&cert_der);
        std::fs::write(out_dir.join(format!("cert_{i}.pem")), &pem).unwrap();
    }

    println!("\n=== Interop test data written to {} ===", out_dir.display());
    println!("Log ID: {log_id}");
    println!("Subtree: [0, 16)");
    println!("Subtree hash (base64): {hash_b64}");
    println!("Subtree hash (hex): {}", hex::encode(subtree_hash));
    println!("Certs: cert_1.pem through cert_15.pem");
}
