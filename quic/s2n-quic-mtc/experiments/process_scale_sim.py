#!/usr/bin/env python3
"""Process MTC scale simulation JSON output into tables.

Usage:
    cargo test -p s2n-quic-mtc --release --test scale_sim -- --nocapture 2>/dev/null | python3 scripts/process_scale_sim.py
    # or from saved JSON:
    python3 scripts/process_scale_sim.py < results.json
"""

import json
import sys

MLDSA44 = 2420
MLDSA44_3X = 3 * MLDSA44
PER_COSIGNER = 77  # u8 len + ~10 byte id + u16 len + 64 byte Ed25519 sig

def main():
    data = json.load(sys.stdin)

    print("=== MTC Scale Simulation Results ===")
    print("Parameters: 7-day cert lifetime, hourly landmarks, SHA-256\n")

    # Proof sizes
    print(f"{'Scale':<12} {'Entries/hr':>12} {'Landmarks':>10} {'Subtrees':>10} "
          f"{'Client State':>14} {'Landmark Proof':>16} {'Full Proof':>14}")
    print("-" * 94)
    for r in data:
        cs_kb = r["client_state_bytes"] / 1024
        print(f"{r['label']:<12} {r['entries_per_hour']:>12,} {r['max_active_landmarks']:>10} "
              f"{r['active_subtrees']:>10} {cs_kb:>11.1f} KB "
              f"{r['landmark_proof_bytes']:>6} B ({r['landmark_proof_hashes']:>2}h) "
              f"{r['full_proof_bytes']:>6} B ({r['full_proof_hashes']:>2}h)")

    # Size comparison
    print(f"\n{'Scale':<12} {'Landmark Cert':>14} {'ML-DSA-44':>14} {'3x ML-DSA-44':>14} {'Savings':>10}")
    print("-" * 68)
    for r in data:
        total = r["landmark_proof_bytes"] + 20
        print(f"{r['label']:<12} {total:>11} B {MLDSA44:>11} B {MLDSA44_3X:>11} B "
              f"{MLDSA44 / total:>9.0f}x")

    # Standalone with cosigners
    print(f"\n{'Scale':<12} {'1 cosigner':>14} {'2 cosigners':>14} {'3 cosigners':>14}")
    print("-" * 58)
    for r in data:
        base = r["landmark_proof_bytes"] + 20
        sizes = [f"{base + PER_COSIGNER * n:>11} B" for n in [1, 2, 3]]
        print(f"{r['label']:<12} {'  '.join(sizes)}")

    # Performance
    print(f"\n{'Scale':<12} {'Total Entries':>14} {'Build Time':>12} {'Throughput':>12}")
    print("-" * 54)
    for r in data:
        print(f"{r['label']:<12} {r['entries_per_week']:>14,} "
              f"{r['build_time_secs']:>9.1f}s "
              f"{r['throughput_per_sec'] / 1e6:>9.1f}M/s")

if __name__ == "__main__":
    main()
