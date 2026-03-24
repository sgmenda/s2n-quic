// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Live MTC demo against twig.sgmenda.people.aws.dev.
//!
//! Shows the full flow: request a cert, get standalone + landmark certs,
//! verify both. Cosignatures are added locally with ML-DSA-87.
//!
//! Run with: cargo run -p s2n-quic-mtc --release --bin live_verify

use base64::Engine as _;
use s2n_quic_mtc::*;

const TWIG: &str = "https://twig.sgmenda.people.aws.dev";
const LOG_ID: &str = "32473.1";
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


fn parse_checkpoint(text: &str) -> (u64, [u8; HASH_SIZE]) {
    let b64 = &base64::engine::general_purpose::STANDARD;
    let lines: Vec<&str> = text.lines().collect();
    let tree_size: u64 = lines[1].parse().unwrap();
    let hash_bytes = b64.decode(lines[2]).unwrap();
    let mut hash = [0u8; HASH_SIZE];
    hash.copy_from_slice(&hash_bytes);
    (tree_size, hash)
}

#[tokio::main]
async fn main() {
    let b64 = &base64::engine::general_purpose::STANDARD;
    let client = reqwest::Client::new();
    let validity = build_validity();
    let subject = build_subject("example.com");

    println!("MTC Live Demo — twig.sgmenda.people.aws.dev");
    println!("=============================================");
    println!();

    // Step 1: Request certificate
    println!("1. Requesting certificate for example.com...");
    let resp: serde_json::Value = client
        .post(format!("{TWIG}/add-entry"))
        .json(&serde_json::json!({
            "spki": b64.encode(SPKI),
            "subject_cn": "example.com",
            "not_before": "250101000000Z",
            "not_after": "260101000000Z",
        }))
        .send().await.unwrap()
        .json().await.unwrap();

    let index = resp["index"].as_u64().unwrap();
    let tree_size = resp["tree_size"].as_u64().unwrap();
    println!("   Entry added at index {index} (tree size: {tree_size})");
    println!();

    // Fetch proof components
    let cert_resp: serde_json::Value = client
        .get(format!("{TWIG}/cert/{index}"))
        .send().await.unwrap()
        .json().await.unwrap();

    let inclusion_proof = b64.decode(cert_resp["inclusion_proof"].as_str().unwrap()).unwrap();
    let start = cert_resp["subtree_start"].as_u64().unwrap();
    let end = cert_resp["subtree_end"].as_u64().unwrap();
    let subtree_hash_bytes = b64.decode(cert_resp["subtree_hash"].as_str().unwrap()).unwrap();
    let mut subtree_hash = [0u8; HASH_SIZE];
    subtree_hash.copy_from_slice(&subtree_hash_bytes);

    // Fetch checkpoint
    let checkpoint_text = client
        .get(format!("{TWIG}/checkpoint"))
        .send().await.unwrap()
        .text().await.unwrap();
    let (ckpt_size, root_hash) = parse_checkpoint(&checkpoint_text);

    // Fetch cosigner public key from twig
    let cosigner_resp: serde_json::Value = client
        .get(format!("{TWIG}/cosigner"))
        .send().await.unwrap()
        .json().await.unwrap();
    let cosigner_id = b64.decode(cosigner_resp["cosigner_id"].as_str().unwrap()).unwrap();
    let cosigner_pk = b64.decode(cosigner_resp["public_key"].as_str().unwrap()).unwrap();

    // Extract cosignature from cert response
    let cosig_entry = &cert_resp["cosignatures"][0];
    let cosig = b64.decode(cosig_entry["signature"].as_str().unwrap()).unwrap();
    let cosig_id = b64.decode(cosig_entry["cosigner_id"].as_str().unwrap()).unwrap();

    // Step 2: Build standalone cert with twig's ML-DSA-87 cosignature
    println!("2. Building standalone cert with twig's ML-DSA-87 cosignature...");

    let cosig_bytes = encode_cosignatures(&[(cosig_id.as_slice(), cosig.as_slice())]);
    let mut standalone_proof = Vec::new();
    standalone_proof.extend_from_slice(&start.to_be_bytes());
    standalone_proof.extend_from_slice(&end.to_be_bytes());
    standalone_proof.extend_from_slice(&(inclusion_proof.len() as u16).to_be_bytes());
    standalone_proof.extend_from_slice(&inclusion_proof);
    standalone_proof.extend_from_slice(&(cosig_bytes.len() as u16).to_be_bytes());
    standalone_proof.extend_from_slice(&cosig_bytes);

    let standalone_cert = build_mtc_cert(
        index, LOG_ID, V3, &validity, &subject, SPKI, &[], &standalone_proof,
    );

    let standalone_anchor = TrustAnchor {
        log_id: LOG_ID.as_bytes().to_vec(),
        cosigners: vec![TrustedCosigner {
            cosigner_id: cosigner_id.to_vec(),
            public_key: cosigner_pk.to_vec(),
            algorithm: CosignerAlgorithm::MlDsa87,
        }],
        quorum: 1,
        trusted_subtrees: vec![],
    };

    // Step 3: Verify standalone cert
    println!("3. Verifying standalone cert...");
    match verify_mtc_cert(&standalone_cert, &standalone_anchor) {
        Ok(()) => println!("   ✓ Standalone cert verified ({} bytes)", standalone_cert.len()),
        Err(e) => println!("   ✗ Failed: {e:?}"),
    }
    println!("   (includes {}-byte ML-DSA-87 cosignature from twig)", cosig.len());
    println!();

    // Step 4: Build landmark cert (no cosignatures)
    println!("4. Building landmark cert (no cosignatures)...");
    let landmark_proof = build_mtc_proof(start, end, &inclusion_proof);
    let landmark_cert = build_mtc_cert(
        index, LOG_ID, V3, &validity, &subject, SPKI, &[], &landmark_proof,
    );

    let landmark_anchor = TrustAnchor {
        log_id: LOG_ID.as_bytes().to_vec(),
        cosigners: vec![],
        quorum: 0,
        trusted_subtrees: vec![(Subtree::new(start, end), root_hash)],
    };

    // Step 5: Verify landmark cert
    println!("5. Verifying landmark cert against checkpoint (tree size {ckpt_size})...");
    match verify_mtc_cert(&landmark_cert, &landmark_anchor) {
        Ok(()) => println!("   ✓ Landmark cert verified ({} bytes)", landmark_cert.len()),
        Err(e) => println!("   ✗ Failed: {e:?}"),
    }
    println!();

    // Summary
    println!("Summary");
    println!("───────");
    println!("  Standalone cert (ML-DSA-87): {:>6} bytes", standalone_cert.len());
    println!("  Landmark cert (no sigs):     {:>6} bytes", landmark_cert.len());
    println!("  ML-DSA-87 signature alone:   {:>6} bytes", cosig.len());
    println!();
    println!("  The landmark cert is {:.0}x smaller than the ML-DSA-87 signature.",
        cosig.len() as f64 / landmark_cert.len() as f64);
}
