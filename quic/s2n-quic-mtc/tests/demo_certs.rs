// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests verifying demo-tool-generated MTC certificates.

use aws_lc_rs::digest;
use s2n_quic_mtc::{evaluate_inclusion_proof, hash_leaf, Subtree, TreeHash, HASH_SIZE};
use x509_parser::prelude::*;

/// Parse the MTCProof from a certificate's signatureValue.
/// Layout: u64 start, u64 end, u16-len inclusion_proof, u16-len signatures
fn parse_mtc_proof(sig_value: &[u8]) -> (u64, u64, &[u8], &[u8]) {
    let mut r = sig_value;
    let start = u64::from_be_bytes(r[..8].try_into().unwrap());
    r = &r[8..];
    let end = u64::from_be_bytes(r[..8].try_into().unwrap());
    r = &r[8..];
    let proof_len = u16::from_be_bytes(r[..2].try_into().unwrap()) as usize;
    r = &r[2..];
    let inclusion_proof = &r[..proof_len];
    r = &r[proof_len..];
    let sigs_len = u16::from_be_bytes(r[..2].try_into().unwrap()) as usize;
    r = &r[2..];
    let signatures = &r[..sigs_len];
    (start, end, inclusion_proof, signatures)
}

/// Compute the entry_hash for a plants-02 TBSCertificateLogEntry.
///
/// We walk the raw DER TBSCertificate fields and reconstruct the log entry.
/// For plants-02 (no SEQUENCE wrapper):
///   0x0001 || version || issuer || validity || subject
///   || subjectPublicKeyAlgorithm || OCTET_STRING(SHA256(SPKI)) || extensions
fn compute_entry_hash(tbs_der: &[u8]) -> TreeHash {
    // Skip the outer SEQUENCE tag+length to get TBS content
    let (content, _) = read_tlv(tbs_der);

    let mut cursor = content;

    // version [0] EXPLICIT — context-specific constructed tag 0xa0
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
    // Extract algorithm from SPKI: skip SEQUENCE tag+len, then read first element
    let (spki_content, _) = read_tlv(spki_bytes);
    let (_, alg_consumed) = read_tlv_raw(spki_content);
    let spki_alg_bytes = &spki_content[..alg_consumed];
    cursor = &cursor[spki_consumed..];

    // Hash the full SPKI
    let spki_hash = digest::digest(&digest::SHA256, spki_bytes);

    // Everything remaining is extensions/uniqueIDs
    let after_spki = cursor;

    // Build the entry
    let mut entry = Vec::new();
    entry.extend_from_slice(&[0x00, 0x01]); // tbs_cert_entry type
    entry.extend_from_slice(version_bytes);
    entry.extend_from_slice(issuer_bytes);
    entry.extend_from_slice(validity_bytes);
    entry.extend_from_slice(subject_bytes);
    entry.extend_from_slice(spki_alg_bytes);
    entry.push(0x04); // OCTET STRING tag
    entry.push(HASH_SIZE as u8);
    entry.extend_from_slice(spki_hash.as_ref());
    entry.extend_from_slice(after_spki);

    hash_leaf(&entry)
}

/// Read a DER TLV, returning (content_bytes, total_consumed_bytes).
fn read_tlv(data: &[u8]) -> (&[u8], usize) {
    let (tag_len, content_offset, content_len) = parse_tl(data);
    let _ = tag_len;
    let total = content_offset + content_len;
    (&data[content_offset..total], total)
}

/// Read a DER TLV, returning (content_bytes, total_consumed_bytes).
fn read_tlv_raw(data: &[u8]) -> (&[u8], usize) {
    let (_, total) = read_tlv(data);
    (&data[..total], total)
}

/// Parse tag + length, returning (tag_byte_count, content_offset, content_length).
fn parse_tl(data: &[u8]) -> (usize, usize, usize) {
    // Tag: single byte for our purposes (no high-tag-number form needed)
    let tag_len = 1;
    let len_byte = data[tag_len];
    if len_byte < 0x80 {
        (tag_len, tag_len + 1, len_byte as usize)
    } else {
        let num_len_bytes = (len_byte & 0x7f) as usize;
        let mut length: usize = 0;
        for i in 0..num_len_bytes {
            length = (length << 8) | data[tag_len + 1 + i] as usize;
        }
        (tag_len, tag_len + 1 + num_len_bytes, length)
    }
}

fn decode_subtree_hash(b64: &str) -> TreeHash {
    let bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        b64,
    )
    .unwrap();
    bytes.try_into().unwrap()
}

fn load_cert(path: &str) -> Vec<u8> {
    let pem_data = std::fs::read(path).unwrap();
    let parsed = ::pem::parse(pem_data).unwrap();
    parsed.into_contents()
}

fn verify_demo_cert(cert_path: &str, expected_subtree_hash: &str) {
    let der = load_cert(cert_path);
    let (_, cert) = X509Certificate::from_der(&der).unwrap();

    // Extract serial number as index
    let index = cert.raw_serial();
    let index = {
        let mut val: u64 = 0;
        for b in index {
            val = (val << 8) | (*b as u64);
        }
        val
    };

    // The signatureValue in x509-parser is the BitString value (after unused bits byte)
    let sig_value = cert.signature_value.data;

    let (start, end, inclusion_proof, _signatures) = parse_mtc_proof(&sig_value);
    let subtree = Subtree::new(start, end);

    // Compute entry_hash from the TBSCertificate
    let entry_hash = compute_entry_hash(cert.tbs_certificate.as_ref());

    // Evaluate the inclusion proof
    let computed_subtree_hash =
        evaluate_inclusion_proof(inclusion_proof, index, &entry_hash, &subtree)
            .expect("inclusion proof evaluation failed");

    let expected: TreeHash = decode_subtree_hash(expected_subtree_hash);
    assert_eq!(
        computed_subtree_hash, expected,
        "subtree hash mismatch for {cert_path} (index={index}, subtree=[{start}, {end}))"
    );
}

#[test]
fn verify_cert_11_0() {
    // Subtree [8, 12) with hash HeITIcWA8kMcddChNLq2w6p5Sa4cTm60QoAHnAW+mvs=
    verify_demo_cert(
        "testdata/interop/cert_11_0.pem",
        "HeITIcWA8kMcddChNLq2w6p5Sa4cTm60QoAHnAW+mvs=",
    );
}

#[test]
fn verify_cert_11_1() {
    // Subtree [8, 16) with hash Udlthrq0wpsLog+7uyV030trgLsS1G+10QWmOop3XMk=
    verify_demo_cert(
        "testdata/interop/cert_11_1.pem",
        "Udlthrq0wpsLog+7uyV030trgLsS1G+10QWmOop3XMk=",
    );
}

#[test]
fn verify_cert_11_2() {
    // Subtree [0, 16) with hash LevI+1472IKCyxgHo6LNYVZL25o8jLpWpew/67tFwno=
    verify_demo_cert(
        "testdata/interop/cert_11_2.pem",
        "LevI+1472IKCyxgHo6LNYVZL25o8jLpWpew/67tFwno=",
    );
}

#[test]
fn verify_cert_22_0() {
    // Subtree [16, 24) with hash NCSaVsLNpA0AT1ZF2OhhJFsWuprFDsjhFHwxPuTr1J8=
    verify_demo_cert(
        "testdata/interop/cert_22_0.pem",
        "NCSaVsLNpA0AT1ZF2OhhJFsWuprFDsjhFHwxPuTr1J8=",
    );
}

#[test]
fn verify_cert_2025_0() {
    // Subtree [1024, 2026) with hash F6HpMOkc67Fwh4HCXoFD74l+RgRF7aa5UjVwGz+Lwb4=
    verify_demo_cert(
        "testdata/interop/cert_2025_0.pem",
        "F6HpMOkc67Fwh4HCXoFD74l+RgRF7aa5UjVwGz+Lwb4=",
    );
}
