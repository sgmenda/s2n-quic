# s2n-quic-mtc

Experimental Rust implementation of
[`draft-ietf-plants-merkle-tree-certs`](https://github.com/davidben/merkle-tree-certs/blob/7fecd363ca8274b464fa9a585964d9818f919322/draft-ietf-plants-merkle-tree-certs.md)
(pinned to commit `7fecd363`), built for experimentation and spec feedback.

Interop-tested against the
[demo tool](https://github.com/davidben/merkle-tree-certs/tree/main/demo)
in the spec repo (plants-02).

## Structure

- `src/` — library: tree, proofs, entries, cosigners (Ed25519 + ML-DSA-87), verification
- `src/bin/twig.rs` — experimental issuance log at `twig.sgmenda.people.aws.dev`
- `experiments/` — cert_sizes, live_verify, scale_sim
- `deploy/` — Dockerfile + Caddy
- `specs/merkle-tree-certs/` — duvet compliance tracking

## Build & Test

```bash
cargo test -p s2n-quic-mtc
cargo run -p s2n-quic-mtc --release --bin twig  # local server at :8080
```

## Experiments

### cert_sizes — MTC size comparison

```bash
cargo run -p s2n-quic-mtc --release --bin cert_sizes
```

Compares landmark and standalone MTC certs with Ed25519 and ML-DSA-87
cosigners. Key results from a 1000-entry tree:

| Type | Cert size | Proof |
|---|---|---|
| Landmark (no sigs) | 500 B | 8×32 B |
| Ed25519 (1 cosig) | 571 B | 8×32 B |
| ML-DSA-87 (1 cosig) | 5,134 B | 8×32 B |
| ML-DSA-87 (3 cosigs) | 14,402 B | 8×32 B |

Landmark certs are ~500 B regardless of signature algorithm — an ML-DSA-87
signature alone is 4,627 B. Proofs grow logarithmically: a 1M-entry tree
only adds 4 more hashes (128 B) over a 1000-entry tree.

### scale_sim — large-scale simulation

```bash
cargo run -p s2n-quic-mtc --release --bin scale_sim 2>/dev/null \
  | python3 experiments/process_scale_sim.py
```

Simulates MTC issuance at 25M–250M certs/week with 7-day lifetime and
hourly landmarks:

| Scale | Landmark cert | Client state | Build time | Throughput |
|---|---|---|---|---|
| 25M/week | 564 B | 10.5 KB | 4.7s | 5.3M/s |
| 50M/week | 596 B | 10.5 KB | 9.1s | 5.5M/s |
| 100M/week | 628 B | 10.5 KB | 19.4s | 5.2M/s |
| 250M/week | 628 B | 10.5 KB | 49.1s | 5.1M/s |

Landmark certs stay under 650 B even at 250M certs/week. Client state is
10.5 KB per CA regardless of scale (168 landmarks × 2 subtrees × 32 B).

## Thanks

Thanks to davidben for the MTC drafts and the Go demo tool, and to the IETF
PLANTS working group.
