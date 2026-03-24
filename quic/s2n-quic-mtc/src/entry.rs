// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! MerkleTreeCertEntry construction and MTC certificate generation.
//!
//! Implements the entry format from draft-ietf-plants-merkle-tree-certs
//! Section 5.2 (Log Entries) and Section 6.1 (Certificate Format).

use crate::tree::{hash_leaf, TreeHash, HASH_SIZE};
use aws_lc_rs::digest;

/// OID for id-alg-mtcProof (experimental): 1.3.6.1.4.1.44363.47.0
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-6.1
//# The TBSCertificate's signature and the Certificate's
//# signatureAlgorithm MUST contain an AlgorithmIdentifier whose
//# algorithm is id-alg-mtcProof, defined below, and whose parameters
//# is omitted.
const OID_ALG_MTC_PROOF: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xda, 0x4b, 0x2f, 0x00];

/// OID for id-rdna-trustAnchorID (experimental): 1.3.6.1.4.1.44363.47.1
//
//= specs/merkle-tree-certs/draft-ietf-tls-trust-anchor-ids.txt#section-3
//# A trust anchor ID is defined with an OID under the OID arc of some
//# PEN.  For compactness, they are represented as relative object
//# identifiers (see Section 33 of [X680]), relative to the OID prefix
//# 1.3.6.1.4.1.
const OID_RDNA_TRUST_ANCHOR_ID: &[u8] =
    &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xda, 0x4b, 0x2f, 0x01];

/// Build a MerkleTreeCertEntry (plants-02 format, no SEQUENCE wrapper) and
/// compute its entry_hash.
///
/// The entry is: `0x0001 || version || issuer || validity || subject ||
/// subjectPublicKeyAlgorithm || OCTET_STRING(SHA256(SPKI)) || after_spki`
///
/// Returns `(entry_bytes, entry_hash)`.
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-5.3
//# The entry at index zero of every issuance log MUST be
//# of type null_entry.
//
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-5.3
//# Other entries MUST NOT use null_entry.
//
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-5.3
//# The issuer field
//# MUST be the issuance log's log ID as a PKIX distinguished name, as
//# described in Section 5.2.
pub fn build_entry(
    version: &[u8],
    issuer: &[u8],
    validity: &[u8],
    subject: &[u8],
    spki: &[u8],
    after_spki: &[u8],
) -> (Vec<u8>, TreeHash) {
    // Extract subjectPublicKeyAlgorithm from SPKI
    let (spki_content, _) = read_tlv(spki);
    let (_, alg_len) = read_tlv_raw(spki_content);
    let spki_alg = &spki_content[..alg_len];

    // Hash the full SPKI
    let spki_hash = digest::digest(&digest::SHA256, spki);

    let mut entry = Vec::new();
    entry.extend_from_slice(&[0x00, 0x01]); // tbs_cert_entry type
    entry.extend_from_slice(version);
    entry.extend_from_slice(issuer);
    entry.extend_from_slice(validity);
    entry.extend_from_slice(subject);
    entry.extend_from_slice(spki_alg);
    entry.push(0x04); // OCTET STRING tag
    entry.push(HASH_SIZE as u8);
    entry.extend_from_slice(spki_hash.as_ref());
    entry.extend_from_slice(after_spki);

    let hash = hash_leaf(&entry);
    (entry, hash)
}

/// Build an MTCProof byte string: `start || end || len(proof) || proof || len(sigs) || sigs`
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-6.1
//# start and end MUST contain the corresponding parameters of the chosen
//# subtree.
//
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-6.1
//# inclusion_proof MUST contain a subtree inclusion proof
//# (Section 4.3) for the log entry and the subtree.
pub fn build_mtc_proof(start: u64, end: u64, inclusion_proof: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&start.to_be_bytes());
    buf.extend_from_slice(&end.to_be_bytes());
    // inclusion_proof with u16 length prefix
    buf.extend_from_slice(&(inclusion_proof.len() as u16).to_be_bytes());
    buf.extend_from_slice(inclusion_proof);
    // empty signatures with u16 length prefix
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf
}

/// Build a DER-encoded X.509 MTC certificate.
///
/// This constructs a minimal valid X.509 Certificate with:
/// - The provided TBSCertificate fields
/// - signatureAlgorithm = id-alg-mtcProof
/// - signatureValue = MTCProof
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-6.1
//# The TBSCertificate's version, issuer, validity, subject,
//# issuerUniqueID, subjectUniqueID, and extensions MUST be equal to the
//# corresponding fields of the TBSCertificateLogEntry.
//
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-6.1
//# The TBSCertificate's serialNumber MUST contain the zero-based index
//# of the TBSCertificateLogEntry in the log.
//
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-6.1
//# Per Section 5.3, this means issuer MUST be the
//# issuance log's log ID as a PKIX distinguished name, as described in
//# Section 5.2.
//
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-6.1
//# Its algorithm field MUST match the
//# TBSCertificateLogEntry's subjectPublicKeyAlgorithm.
//
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-6.1
//# Its hash MUST
//# match the TBSCertificateLogEntry's subjectPublicKeyInfoHash.
//
//= specs/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt#section-6.1
//# The most significant bit of the first octet of the
//# signature value SHALL become the first bit of the bit string, and so
//# on through the least significant bit of the last octet of the
//# signature value, which SHALL become the last bit of the bit string.
pub fn build_mtc_cert(
    serial: u64,
    log_id: &str,
    version: &[u8],
    validity: &[u8],
    subject: &[u8],
    spki: &[u8],
    after_spki: &[u8],
    mtc_proof: &[u8],
) -> Vec<u8> {
    let issuer = build_issuer_name(log_id);
    let sig_alg = build_sig_alg();
    let serial_bytes = build_serial(serial);

    // TBSCertificate SEQUENCE
    let mut tbs = Vec::new();
    tbs.extend_from_slice(version);
    tbs.extend_from_slice(&serial_bytes);
    tbs.extend_from_slice(&sig_alg);
    tbs.extend_from_slice(&issuer);
    tbs.extend_from_slice(validity);
    tbs.extend_from_slice(subject);
    tbs.extend_from_slice(spki);
    tbs.extend_from_slice(after_spki);
    let tbs_seq = wrap_sequence(&tbs);

    // signatureValue BIT STRING (0 unused bits + MTCProof)
    let mut sig_bits = vec![0x00]; // unused bits
    sig_bits.extend_from_slice(mtc_proof);
    let sig_value = wrap_tag(0x03, &sig_bits);

    // Certificate SEQUENCE
    let mut cert = Vec::new();
    cert.extend_from_slice(&tbs_seq);
    cert.extend_from_slice(&sig_alg);
    cert.extend_from_slice(&sig_value);
    wrap_sequence(&cert)
}

// --- DER helpers ---

fn build_serial(serial: u64) -> Vec<u8> {
    // INTEGER encoding of serial
    let bytes = serial.to_be_bytes();
    // Strip leading zeros but keep at least one byte
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let significant = &bytes[start..];
    // If high bit is set, prepend a 0x00
    if significant[0] & 0x80 != 0 {
        let mut val = vec![0x00];
        val.extend_from_slice(significant);
        wrap_tag(0x02, &val)
    } else {
        wrap_tag(0x02, significant)
    }
}

fn build_sig_alg() -> Vec<u8> {
    // AlgorithmIdentifier SEQUENCE { OID, no parameters }
    let oid = wrap_tag(0x06, OID_ALG_MTC_PROOF);
    wrap_sequence(&oid)
}

//= specs/merkle-tree-certs/draft-ietf-tls-trust-anchor-ids.txt#section-3.1
//# When trust anchors are represented as X.509 certificates, the X.509
//# trust anchor ID extension MAY be used to carry this ID.
fn build_issuer_name(log_id: &str) -> Vec<u8> {
    // Name SEQUENCE { SET { SEQUENCE { OID, UTF8String(log_id) } } }
    let oid = wrap_tag(0x06, OID_RDNA_TRUST_ANCHOR_ID);
    let val = wrap_tag(0x0c, log_id.as_bytes()); // UTF8String
    let attr_seq = wrap_sequence(&[oid, val].concat());
    let rdn_set = wrap_tag(0x31, &attr_seq); // SET
    wrap_sequence(&rdn_set)
}

fn wrap_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    encode_length(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

fn wrap_sequence(content: &[u8]) -> Vec<u8> {
    wrap_tag(0x30, content)
}

fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

// --- DER reading helpers (also used by tests/demo_certs.rs) ---

/// Read a DER TLV, returning (content_bytes, total_consumed_bytes).
pub fn read_tlv(data: &[u8]) -> (&[u8], usize) {
    let (content_offset, content_len) = parse_tl(data);
    let total = content_offset + content_len;
    (&data[content_offset..total], total)
}

/// Read a DER TLV, returning (full_tlv_bytes, total_consumed_bytes).
pub fn read_tlv_raw(data: &[u8]) -> (&[u8], usize) {
    let (_, total) = read_tlv(data);
    (&data[..total], total)
}

fn parse_tl(data: &[u8]) -> (usize, usize) {
    let tag_len = 1;
    let len_byte = data[tag_len];
    if len_byte < 0x80 {
        (tag_len + 1, len_byte as usize)
    } else {
        let num_len_bytes = (len_byte & 0x7f) as usize;
        let mut length: usize = 0;
        for i in 0..num_len_bytes {
            length = (length << 8) | data[tag_len + 1 + i] as usize;
        }
        (tag_len + 1 + num_len_bytes, length)
    }
}
