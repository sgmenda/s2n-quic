// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! MTC demo: cert size comparison between Ed25519 and ML-DSA-87.
//!
//! Builds trees, generates landmark and standalone certs with varying
//! cosigner counts, verifies each one, and prints comparison tables.
//!
//! Run with: cargo run -p s2n-quic-mtc --release --bin cert_sizes

use s2n_quic_mtc::*;

const LOG_ID: &str = "32473.1";
const V3: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x02];

// Same SPKI used by the Go demo tool (P-256)
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

fn build_validity() -> Vec<u8> {
    let nb = b"250101000000Z";
    let na = b"260101000000Z";
    let mut v = vec![0x30, (2 + nb.len() + 2 + na.len()) as u8];
    v.push(0x17); v.push(nb.len() as u8); v.extend_from_slice(nb);
    v.push(0x17); v.push(na.len() as u8); v.extend_from_slice(na);
    v
}

fn build_subject(cn: &str) -> Vec<u8> {
    let oid = &[0x06, 0x03, 0x55, 0x04, 0x03];
    let val: Vec<u8> = [vec![0x0c, cn.len() as u8], cn.as_bytes().to_vec()].concat();
    let inner: Vec<u8> = [oid.to_vec(), val].concat();
    let attr = [vec![0x30, inner.len() as u8], inner].concat();
    let rdn = [vec![0x31, attr.len() as u8], attr].concat();
    [vec![0x30, rdn.len() as u8], rdn].concat()
}

fn build_issuer(log_id: &str) -> Vec<u8> {
    // Must use OID_RDNA_TRUST_ANCHOR_ID to match entry.rs build_issuer_name
    let oid = &[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xda, 0x4b, 0x2f, 0x01];
    let val: Vec<u8> = [vec![0x0c, log_id.len() as u8], log_id.as_bytes().to_vec()].concat();
    let inner: Vec<u8> = [oid.to_vec(), val].concat();
    let attr = [vec![0x30, inner.len() as u8], inner].concat();
    let rdn = [vec![0x31, attr.len() as u8], attr].concat();
    [vec![0x30, rdn.len() as u8], rdn].concat()
}

/// Build a tree with `n` entries and return (tree, entry_index, entry_hash).
/// The target entry is at index n-1.
fn build_tree(n: u64) -> (MerkleTreeBuilder, u64) {
    let mut tree = MerkleTreeBuilder::new();
    let issuer = build_issuer(LOG_ID);
    let validity = build_validity();
    let subject = build_subject("demo.example");

    // Null entry at index 0
    tree.append(&[0x00, 0x00]);

    // Filler entries
    for i in 1..n - 1 {
        tree.append(&i.to_be_bytes());
    }

    // Target entry at index n-1
    let (_, entry_hash) = build_entry(V3, &issuer, &validity, &subject, SPKI, &[]);
    tree.append_hash(entry_hash);

    (tree, n - 1)
}

struct CertResult {
    label: String,
    cert_size: usize,
    proof_hashes: usize,
    verified: bool,
}

fn make_landmark_cert(
    tree: &MerkleTreeBuilder,
    index: u64,
) -> CertResult {
    let subtree = Subtree::new(0, tree.size());
    let proof = tree.inclusion_proof(index, &subtree);
    let mtc_proof = build_mtc_proof(0, tree.size(), &proof);
    let cert = build_mtc_cert(
        index, LOG_ID, V3, &build_validity(), &build_subject("demo.example"),
        SPKI, &[], &mtc_proof,
    );

    let anchor = TrustAnchor {
        log_id: LOG_ID.as_bytes().to_vec(),
        cosigners: vec![],
        quorum: 0,
        trusted_subtrees: vec![(subtree, tree.subtree_hash(&subtree))],
    };
    let verified = verify_mtc_cert(&cert, &anchor).is_ok();

    CertResult {
        label: "Landmark".into(),
        cert_size: cert.len(),
        proof_hashes: proof.len() / HASH_SIZE,
        verified,
    }
}

fn make_standalone_cert_ed25519(
    tree: &MerkleTreeBuilder,
    index: u64,
    num_cosigners: usize,
) -> CertResult {
    let subtree = Subtree::new(0, tree.size());
    let subtree_hash = tree.subtree_hash(&subtree);
    let proof = tree.inclusion_proof(index, &subtree);

    let cosigners: Vec<Cosigner> = (0..num_cosigners)
        .map(|i| Cosigner::generate(format!("ed-{i}").as_bytes()))
        .collect();

    let sigs: Vec<(Vec<u8>, Vec<u8>)> = cosigners.iter()
        .map(|c| (c.cosigner_id().to_vec(), c.sign_subtree(LOG_ID.as_bytes(), 0, tree.size(), &subtree_hash)))
        .collect();
    let sig_refs: Vec<(&[u8], &[u8])> = sigs.iter().map(|(id, s)| (id.as_slice(), s.as_slice())).collect();
    let cosig_bytes = encode_cosignatures(&sig_refs);

    let mut mtc_proof_bytes = Vec::new();
    mtc_proof_bytes.extend_from_slice(&0u64.to_be_bytes());
    mtc_proof_bytes.extend_from_slice(&tree.size().to_be_bytes());
    mtc_proof_bytes.extend_from_slice(&(proof.len() as u16).to_be_bytes());
    mtc_proof_bytes.extend_from_slice(&proof);
    mtc_proof_bytes.extend_from_slice(&(cosig_bytes.len() as u16).to_be_bytes());
    mtc_proof_bytes.extend_from_slice(&cosig_bytes);

    let cert = build_mtc_cert(
        index, LOG_ID, V3, &build_validity(), &build_subject("demo.example"),
        SPKI, &[], &mtc_proof_bytes,
    );

    let anchor = TrustAnchor {
        log_id: LOG_ID.as_bytes().to_vec(),
        cosigners: cosigners.iter().map(|c| TrustedCosigner {
            cosigner_id: c.cosigner_id().to_vec(),
            public_key: c.public_key().to_vec(),
            algorithm: CosignerAlgorithm::Ed25519,
        }).collect(),
        quorum: num_cosigners,
        trusted_subtrees: vec![],
    };
    let verified = verify_mtc_cert(&cert, &anchor).is_ok();

    CertResult {
        label: format!("Ed25519 ({num_cosigners} cosig)"),
        cert_size: cert.len(),
        proof_hashes: proof.len() / HASH_SIZE,
        verified,
    }
}

fn make_standalone_cert_ml_dsa(
    tree: &MerkleTreeBuilder,
    index: u64,
    num_cosigners: usize,
) -> CertResult {
    let subtree = Subtree::new(0, tree.size());
    let subtree_hash = tree.subtree_hash(&subtree);
    let proof = tree.inclusion_proof(index, &subtree);

    let cosigners: Vec<MlDsaCosigner> = (0..num_cosigners)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[0] = i as u8;
            MlDsaCosigner::from_seed(format!("pq-{i}").as_bytes(), &seed)
        })
        .collect();

    let sigs: Vec<(Vec<u8>, Vec<u8>)> = cosigners.iter()
        .map(|c| (c.cosigner_id().to_vec(), c.sign_subtree(LOG_ID.as_bytes(), 0, tree.size(), &subtree_hash)))
        .collect();
    let sig_refs: Vec<(&[u8], &[u8])> = sigs.iter().map(|(id, s)| (id.as_slice(), s.as_slice())).collect();
    let cosig_bytes = encode_cosignatures(&sig_refs);

    let mut mtc_proof_bytes = Vec::new();
    mtc_proof_bytes.extend_from_slice(&0u64.to_be_bytes());
    mtc_proof_bytes.extend_from_slice(&tree.size().to_be_bytes());
    mtc_proof_bytes.extend_from_slice(&(proof.len() as u16).to_be_bytes());
    mtc_proof_bytes.extend_from_slice(&proof);
    mtc_proof_bytes.extend_from_slice(&(cosig_bytes.len() as u16).to_be_bytes());
    mtc_proof_bytes.extend_from_slice(&cosig_bytes);

    let cert = build_mtc_cert(
        index, LOG_ID, V3, &build_validity(), &build_subject("demo.example"),
        SPKI, &[], &mtc_proof_bytes,
    );

    let anchor = TrustAnchor {
        log_id: LOG_ID.as_bytes().to_vec(),
        cosigners: cosigners.iter().map(|c| TrustedCosigner {
            cosigner_id: c.cosigner_id().to_vec(),
            public_key: c.public_key().to_vec(),
            algorithm: CosignerAlgorithm::MlDsa87,
        }).collect(),
        quorum: num_cosigners,
        trusted_subtrees: vec![],
    };
    let verified = verify_mtc_cert(&cert, &anchor).is_ok();

    CertResult {
        label: format!("ML-DSA-87 ({num_cosigners} cosig)"),
        cert_size: cert.len(),
        proof_hashes: proof.len() / HASH_SIZE,
        verified,
    }
}

fn main() {
    println!("Merkle Tree Certificates — Size Comparison Demo");
    println!("================================================");
    println!();
    println!("Spec: draft-ietf-plants-merkle-tree-certs (plants-02)");
    println!();

    // --- Table 1: Cert sizes with 1000-entry tree ---
    let tree_size: u64 = 1000;
    let (tree, idx) = build_tree(tree_size);

    println!("Certificate sizes (tree size: {tree_size} entries)");
    println!("─────────────────────────────────────────────────────────────");
    println!("{:<25} {:>10} {:>8}  {}", "Type", "Cert size", "Proof", "Verified");
    println!("{:<25} {:>10} {:>8}  {}", "────", "─────────", "─────", "────────");

    let results: Vec<CertResult> = vec![
        make_landmark_cert(&tree, idx),
        make_standalone_cert_ed25519(&tree, idx, 1),
        make_standalone_cert_ed25519(&tree, idx, 2),
        make_standalone_cert_ed25519(&tree, idx, 3),
        make_standalone_cert_ml_dsa(&tree, idx, 1),
        make_standalone_cert_ml_dsa(&tree, idx, 2),
        make_standalone_cert_ml_dsa(&tree, idx, 3),
    ];

    for r in &results {
        let check = if r.verified { "✓" } else { "✗" };
        println!(
            "{:<25} {:>8} B {:>5}×32B  {}",
            r.label, r.cert_size, r.proof_hashes, check,
        );
    }

    println!();
    println!("For comparison:");
    println!("  Ed25519 signature alone:  64 bytes");
    println!("  ML-DSA-87 signature alone: 4,627 bytes");
    println!("  ML-DSA-87 public key:      2,592 bytes");
    println!();

    // --- Table 2: Proof scaling ---
    println!("Proof size scaling (landmark certs)");
    println!("─────────────────────────────────────────────────────────────");
    println!("{:>12} {:>12} {:>14} {:>10}", "Tree size", "Proof bytes", "Proof hashes", "Cert size");
    println!("{:>12} {:>12} {:>14} {:>10}", "─────────", "───────────", "────────────", "─────────");

    for &n in &[16u64, 256, 1_000, 10_000, 100_000, 1_000_000] {
        let (t, i) = build_tree(n);
        let r = make_landmark_cert(&t, i);
        println!(
            "{:>12} {:>10} B {:>12}×32 {:>8} B",
            n, r.proof_hashes * HASH_SIZE, r.proof_hashes, r.cert_size,
        );
    }

    println!();
    println!("Proofs grow logarithmically: a 1M-entry tree adds only ~6");
    println!("hashes over a 16-entry tree.");
    println!();
    println!("For large-scale simulations (25M–250M certs/week), run:");
    println!("  cargo run -p s2n-quic-mtc --release --bin scale_sim");
}
