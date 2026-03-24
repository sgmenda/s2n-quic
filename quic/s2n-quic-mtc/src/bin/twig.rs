// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Twig — an experimental MTC issuance log server.
//!
//! Single-binary log server with local filesystem persistence and optional TLS.
//!
//! Usage:
//!   twig --data-dir /data/twig
//!   twig --data-dir /data/twig --tls-cert cert.pem --tls-key key.pem --port 443
//!
//! Endpoints:
//!   GET  /checkpoint          — signed checkpoint
//!   GET  /tile/{L}/{N...}     — Merkle tree tile
//!   POST /add-entry           — submit a new entry
//!   GET  /cert/{index}        — retrieve MTC cert for entry

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use aws_lc_rs::rand::SecureRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use s2n_quic_mtc::storage::{CheckpointStore, LocalStore, TileStore};
use s2n_quic_mtc::tile::{self, TILE_WIDTH};
use s2n_quic_mtc::*;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

const ORIGIN: &str = "twig.sgmenda.people.aws.dev";
const LOG_ID: &str = "32473.1";
const V3_VERSION: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x02];

const COSIGNER_ID: &[u8] = b"32473.2.1";

struct LogState {
    tree: MerkleTreeBuilder,
    entry_hashes: Vec<TreeHash>,
    key_pair: Ed25519KeyPair,
    cosigner: MlDsaCosigner,
    store: LocalStore,
    current_checkpoint: Option<String>,
}

#[derive(Deserialize)]
struct AddEntryRequest {
    spki: String,
    subject_cn: String,
    not_before: String,
    not_after: String,
}

#[derive(Serialize)]
struct AddEntryResponse {
    index: u64,
    tree_size: u64,
}

type SharedState = Arc<Mutex<LogState>>;

fn build_validity(not_before: &str, not_after: &str) -> Vec<u8> {
    let nb = { let mut v = vec![0x17, not_before.len() as u8]; v.extend_from_slice(not_before.as_bytes()); v };
    let na = { let mut v = vec![0x17, not_after.len() as u8]; v.extend_from_slice(not_after.as_bytes()); v };
    let mut val = vec![0x30, (nb.len() + na.len()) as u8];
    val.extend_from_slice(&nb);
    val.extend_from_slice(&na);
    val
}

fn build_subject_name(cn: &str) -> Vec<u8> {
    let oid = &[0x06, 0x03, 0x55, 0x04, 0x03];
    let val = { let mut v = vec![0x0c, cn.len() as u8]; v.extend_from_slice(cn.as_bytes()); v };
    let inner: Vec<u8> = [oid.to_vec(), val].concat();
    let attr = [vec![0x30, inner.len() as u8], inner].concat();
    let rdn = [vec![0x31, attr.len() as u8], attr].concat();
    [vec![0x30, rdn.len() as u8], rdn].concat()
}

fn build_issuer_name(log_id: &str) -> Vec<u8> {
    let oid = &[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xda, 0x4b, 0x2f, 0x01];
    let val = { let mut v = vec![0x0c, log_id.len() as u8]; v.extend_from_slice(log_id.as_bytes()); v };
    let inner: Vec<u8> = [oid.to_vec(), val].concat();
    let attr = [vec![0x30, inner.len() as u8], inner].concat();
    let rdn = [vec![0x31, attr.len() as u8], attr].concat();
    [vec![0x30, rdn.len() as u8], rdn].concat()
}

/// Write any new full tiles to storage.
fn flush_tiles(state: &LogState) {
    let n = state.tree.size();
    let full_tiles = n / TILE_WIDTH;
    for i in 0..full_tiles {
        let path = tile::tile_path(0, i, None);
        if !state.store.tile_exists(&path) {
            let start = i * TILE_WIDTH;
            let mut data = Vec::with_capacity(TILE_WIDTH as usize * HASH_SIZE);
            for j in start..start + TILE_WIDTH {
                data.extend_from_slice(&state.tree.get_node(0, j));
            }
            state.store.put_tile(&path, &data).unwrap();
        }
    }
    // Write partial tile
    let partial = n % TILE_WIDTH;
    if partial > 0 {
        let path = tile::tile_path(0, full_tiles, Some(partial));
        let start = full_tiles * TILE_WIDTH;
        let mut data = Vec::new();
        for j in start..n {
            data.extend_from_slice(&state.tree.get_node(0, j));
        }
        state.store.put_tile(&path, &data).unwrap();
    }
}

fn update_checkpoint(state: &mut LogState) {
    let root = if state.tree.size() > 0 {
        state.tree.root_hash()
    } else {
        [0u8; HASH_SIZE]
    };
    let body = checkpoint::checkpoint_body(ORIGIN, state.tree.size(), &root);
    let signed = checkpoint::sign_checkpoint(&body, ORIGIN, &state.key_pair);
    state
        .store
        .compare_and_swap(state.current_checkpoint.as_deref(), &signed)
        .unwrap();
    state.current_checkpoint = Some(signed);
}

/// Rebuild tree state from stored tiles on startup.
fn rebuild_from_storage(store: &LocalStore) -> (MerkleTreeBuilder, Vec<TreeHash>) {
    let mut tree = MerkleTreeBuilder::new();
    let mut entry_hashes = Vec::new();
    let mut tile_index = 0u64;

    // Read full tiles
    loop {
        let path = tile::tile_path(0, tile_index, None);
        match store.get_tile(&path) {
            Ok(data) => {
                for chunk in data.chunks_exact(HASH_SIZE) {
                    let mut h = [0u8; HASH_SIZE];
                    h.copy_from_slice(chunk);
                    tree.append_hash(h);
                    entry_hashes.push(h);
                }
                tile_index += 1;
            }
            Err(_) => break,
        }
    }

    // Read partial tile
    for width in 1..TILE_WIDTH {
        let path = tile::tile_path(0, tile_index, Some(width));
        if let Ok(data) = store.get_tile(&path) {
            for chunk in data.chunks_exact(HASH_SIZE) {
                let mut h = [0u8; HASH_SIZE];
                h.copy_from_slice(chunk);
                tree.append_hash(h);
                entry_hashes.push(h);
            }
            break;
        }
    }

    eprintln!("  rebuilt tree with {} entries from storage", tree.size());
    (tree, entry_hashes)
}

//= specs/merkle-tree-certs/tlog-tiles.md#checkpoints
//# This endpoint is mutable, so its headers SHOULD prevent caching beyond a few
//# seconds.
async fn get_checkpoint(State(state): State<SharedState>) -> impl IntoResponse {
    let state = state.lock().unwrap();
    let ckpt = state.current_checkpoint.clone().unwrap_or_default();
    (
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8"),
         ("cache-control", "no-cache, max-age=5")],
        ckpt,
    )
}

async fn add_entry(
    State(state): State<SharedState>,
    Json(req): Json<AddEntryRequest>,
) -> Result<Json<AddEntryResponse>, StatusCode> {
    use base64::Engine;
    let spki = base64::engine::general_purpose::STANDARD
        .decode(&req.spki)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let validity = build_validity(&req.not_before, &req.not_after);
    let subject = build_subject_name(&req.subject_cn);
    let issuer = build_issuer_name(LOG_ID);

    let (_, entry_hash) = build_entry(V3_VERSION, &issuer, &validity, &subject, &spki, &[]);

    let mut state = state.lock().unwrap();
    let index = state.tree.size();
    state.tree.append_hash(entry_hash);
    state.entry_hashes.push(entry_hash);
    flush_tiles(&state);
    update_checkpoint(&mut state);

    Ok(Json(AddEntryResponse {
        index,
        tree_size: state.tree.size(),
    }))
}

async fn get_cert(
    State(state): State<SharedState>,
    Path(index): Path<u64>,
) -> Result<impl IntoResponse, StatusCode> {
    let state = state.lock().unwrap();
    if index == 0 || index >= state.tree.size() {
        return Err(StatusCode::NOT_FOUND);
    }

    let subtree = Subtree::new(0, state.tree.size());
    let proof_bytes = state.tree.inclusion_proof(index, &subtree);
    let subtree_hash = state.tree.subtree_hash(&subtree);

    // ML-DSA-87 cosignature on the subtree
    let cosig = state.cosigner.sign_subtree(
        LOG_ID.as_bytes(), subtree.start, subtree.end, &subtree_hash,
    );

    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let resp = serde_json::json!({
        "index": index,
        "entry_hash": b64.encode(state.entry_hashes[index as usize]),
        "subtree_start": subtree.start,
        "subtree_end": subtree.end,
        "inclusion_proof": b64.encode(&proof_bytes),
        "subtree_hash": b64.encode(subtree_hash),
        "cosignatures": [{
            "cosigner_id": b64.encode(COSIGNER_ID),
            "algorithm": "ML-DSA-87",
            "signature": b64.encode(&cosig),
        }],
    });

    Ok((
        StatusCode::OK,
        [("content-type", "application/json")],
        serde_json::to_string_pretty(&resp).unwrap(),
    ))
}

async fn get_cosigner(
    State(state): State<SharedState>,
) -> impl IntoResponse {
    let state = state.lock().unwrap();
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let resp = serde_json::json!({
        "cosigner_id": b64.encode(COSIGNER_ID),
        "algorithm": "ML-DSA-87",
        "public_key": b64.encode(state.cosigner.public_key()),
    });
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        serde_json::to_string_pretty(&resp).unwrap(),
    )
}

async fn get_tile(
    State(state): State<SharedState>,
    Path(path): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let state = state.lock().unwrap();

    // Try to read from storage first
    //= specs/merkle-tree-certs/tlog-tiles.md#merkle-tree
    //# This endpoint is immutable, so its caching headers SHOULD be long-lived.
    let tile_path = format!("tile/{path}");
    if let Ok(data) = state.store.get_tile(&tile_path) {
        return Ok((
            StatusCode::OK,
            [("content-type", "application/octet-stream"),
             ("cache-control", "public, max-age=31536000, immutable")],
            data,
        ));
    }

    // Fall back to computing from in-memory tree for partial tiles
    let parts: Vec<&str> = path.splitn(2, '/').collect();
    if parts.len() < 2 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let level: u64 = parts[0].parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    if level != 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    let index_str: String = parts[1]
        .split('/')
        .filter(|s| !s.contains('.'))
        .map(|s| s.trim_start_matches('x'))
        .collect::<Vec<_>>()
        .join("");
    let tile_index: u64 = index_str.parse().map_err(|_| StatusCode::BAD_REQUEST)?;

    let start = tile_index * 256;
    let end = std::cmp::min(start + 256, state.tree.size());
    if start >= state.tree.size() {
        return Err(StatusCode::NOT_FOUND);
    }

    let mut tile_data = Vec::new();
    for i in start..end {
        tile_data.extend_from_slice(&state.tree.get_node(0, i));
    }

    Ok((
        StatusCode::OK,
        [("content-type", "application/octet-stream"),
         ("cache-control", "no-cache")],
        tile_data,
    ))
}

#[tokio::main]
async fn main() {
    let data_dir = std::env::args()
        .skip_while(|a| a != "--data-dir")
        .nth(1)
        .unwrap_or_else(|| "/data/twig".to_string());

    let tls_cert = std::env::args()
        .skip_while(|a| a != "--tls-cert")
        .nth(1);
    let tls_key = std::env::args()
        .skip_while(|a| a != "--tls-key")
        .nth(1);

    let port: u16 = std::env::args()
        .skip_while(|a| a != "--port")
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    eprintln!("🌱 twig starting");
    eprintln!("  data-dir: {data_dir}");

    // Initialize storage
    let store = LocalStore::new(&data_dir).expect("failed to create data dir");

    // Load or generate signing key
    let key_path = std::path::Path::new(&data_dir).join("signing.key");
    let key_pair = if key_path.exists() {
        let pkcs8 = std::fs::read(&key_path).expect("failed to read signing key");
        Ed25519KeyPair::from_pkcs8(&pkcs8).expect("invalid signing key")
    } else {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen failed");
        std::fs::write(&key_path, pkcs8.as_ref()).expect("failed to write signing key");
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("invalid signing key")
    };

    // Load or generate ML-DSA-87 cosigner key
    let cosigner_key_path = std::path::Path::new(&data_dir).join("cosigner.seed");
    let cosigner = if cosigner_key_path.exists() {
        let seed_bytes = std::fs::read(&cosigner_key_path).expect("failed to read cosigner seed");
        let seed: [u8; 32] = seed_bytes.try_into().expect("cosigner seed must be 32 bytes");
        MlDsaCosigner::from_seed(COSIGNER_ID, &seed)
    } else {
        let mut seed = [0u8; 32];
        aws_lc_rs::rand::SystemRandom::new().fill(&mut seed).expect("rng failed");
        std::fs::write(&cosigner_key_path, &seed).expect("failed to write cosigner seed");
        MlDsaCosigner::from_seed(COSIGNER_ID, &seed)
    };

    use base64::Engine;
    eprintln!("  checkpoint key: {}", base64::engine::general_purpose::STANDARD.encode(key_pair.public_key().as_ref()));
    eprintln!("  cosigner key (ML-DSA-87): {} bytes", cosigner.public_key().len());

    // Rebuild tree from storage or start fresh
    let (mut tree, mut entry_hashes) = rebuild_from_storage(&store);
    if tree.size() == 0 {
        eprintln!("  initializing new log with null entry");
        let null_hash = hash_leaf(&[0x00, 0x00]);
        tree.append(&[0x00, 0x00]);
        entry_hashes.push(null_hash);
    }

    let current_checkpoint = store.get().unwrap();
    eprintln!("  tree size: {}", tree.size());

    let mut state = LogState {
        tree,
        entry_hashes,
        key_pair,
        cosigner,
        store,
        current_checkpoint,
    };

    // Write initial checkpoint if none exists
    if state.current_checkpoint.is_none() {
        flush_tiles(&state);
        update_checkpoint(&mut state);
    }

    let shared = Arc::new(Mutex::new(state));

    let app = Router::new()
        .route("/checkpoint", get(get_checkpoint))
        .route("/add-entry", post(add_entry))
        .route("/cert/{index}", get(get_cert))
        .route("/cosigner", get(get_cosigner))
        .route("/tile/{*path}", get(get_tile))
        .with_state(shared);

    let addr = format!("0.0.0.0:{port}");

    if let (Some(cert), Some(key)) = (tls_cert, tls_key) {
        eprintln!("  listening on {addr} (TLS)");
        eprintln!("  cert: {cert}");
        let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
            .await
            .expect("failed to load TLS cert/key");
        axum_server::bind_rustls(addr.parse().unwrap(), config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    } else {
        eprintln!("  listening on {addr} (plain HTTP)");
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    }
}
