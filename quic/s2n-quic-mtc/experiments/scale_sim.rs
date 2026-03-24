// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! MTC scale simulation benchmark.
//!
//! Outputs JSON to stdout. Process with:
//!   cargo run -p s2n-quic-mtc --release --bin scale_sim | python3 scripts/process_scale_sim.py

use s2n_quic_mtc::*;
use std::time::Instant;

struct SimConfig {
    label: &'static str,
    entries_per_week: u64,
    cert_lifetime_days: u64,
    landmark_interval_hours: u64,
}

fn run_simulation(config: &SimConfig) -> serde_json::Value {
    let entries_per_hour = config.entries_per_week / (7 * 24);
    let max_active_landmarks =
        ((config.cert_lifetime_days * 24) / config.landmark_interval_hours + 1) as usize;
    let hours_to_simulate = config.cert_lifetime_days * 24;

    let start = Instant::now();
    let mut tree = MerkleTreeBuilder::new();
    let mut landmarks = LandmarkSequence::new(max_active_landmarks);

    tree.append(&[0x00, 0x00]);

    for hour in 0..hours_to_simulate {
        for _ in 0..entries_per_hour {
            let idx = tree.size();
            tree.append(&idx.to_be_bytes());
        }
        if hour % config.landmark_interval_hours == 0 {
            landmarks.allocate(tree.size());
        }
    }
    let build_time = start.elapsed();

    let active_subtrees = landmarks.active_subtrees();
    let client_state_bytes = active_subtrees.len() * HASH_SIZE;

    let last_subtree = active_subtrees.last().unwrap();
    let sample_idx = last_subtree.start + last_subtree.size() / 2;
    let landmark_proof = tree.inclusion_proof(sample_idx, last_subtree);

    let full_tree = Subtree::new(0, tree.size());
    let full_proof = tree.inclusion_proof(tree.size() / 2, &full_tree);

    serde_json::json!({
        "label": config.label,
        "entries_per_week": config.entries_per_week,
        "entries_per_hour": entries_per_hour,
        "max_active_landmarks": max_active_landmarks,
        "active_subtrees": active_subtrees.len(),
        "client_state_bytes": client_state_bytes,
        "landmark_proof_bytes": landmark_proof.len(),
        "landmark_proof_hashes": landmark_proof.len() / HASH_SIZE,
        "landmark_subtree_size": last_subtree.size(),
        "full_proof_bytes": full_proof.len(),
        "full_proof_hashes": full_proof.len() / HASH_SIZE,
        "build_time_secs": format!("{:.3}", build_time.as_secs_f64()).parse::<f64>().unwrap(),
        "throughput_per_sec": (tree.size() as f64 / build_time.as_secs_f64()).round() as u64,
    })
}

fn main() {
    let configs = vec![
        SimConfig { label: "25M/week",  entries_per_week: 25_000_000,  cert_lifetime_days: 7, landmark_interval_hours: 1 },
        SimConfig { label: "50M/week",  entries_per_week: 50_000_000,  cert_lifetime_days: 7, landmark_interval_hours: 1 },
        SimConfig { label: "100M/week", entries_per_week: 100_000_000, cert_lifetime_days: 7, landmark_interval_hours: 1 },
        SimConfig { label: "250M/week", entries_per_week: 250_000_000, cert_lifetime_days: 7, landmark_interval_hours: 1 },
    ];

    let mut results = Vec::new();
    for config in &configs {
        eprintln!("Running {}...", config.label);
        results.push(run_simulation(config));
    }

    println!("{}", serde_json::to_string_pretty(&results).unwrap());
}
