# Specs

This directory contains the specifications that twig implements, used for
duvet compliance tracking and as reference material.

## Specs

### draft-ietf-plants-merkle-tree-certs (primary)

The MTC spec from the IETF PLANTS WG.

- **Source:** https://github.com/davidben/merkle-tree-certs
- **Pinned to:** commit `7fecd363` (downloaded 2026-03-20)
- **Format:** rendered txt from GitHub Pages
- **SHA-256:** `6e556a1d877486dd5b4b63d70b559818bcb0049b2695cd19d4769d3ecfdcf240`
- **Duvet:** 142 requirements extracted across 30 sections

### draft-ietf-tls-trust-anchor-ids

The Trust Anchor Identifiers spec, used by MTCs for trust anchor negotiation.

- **Source:** https://github.com/tlswg/tls-trust-anchor-ids/
- **Pinned to:** commit `bff3af5d`
- **Format:** rendered txt from GitHub Pages
- **Duvet:** 60 requirements extracted across 15 sections

### C2SP specs (reference)

Transparency log infrastructure specs that twig's HTTP API and storage
format are based on.

- [tlog-tiles.md](tlog-tiles.md) — Tiled transparency log HTTP API
  ([c2sp.org/tlog-tiles](https://c2sp.org/tlog-tiles))
- [tlog-checkpoint.md](tlog-checkpoint.md) — Signed checkpoint format
  ([c2sp.org/tlog-checkpoint](https://c2sp.org/tlog-checkpoint))
- [signed-note.md](signed-note.md) — Signed note format
  ([c2sp.org/signed-note](https://c2sp.org/signed-note))
- [static-ct-api.md](static-ct-api.md) — Static Certificate Transparency API
  ([c2sp.org/static-ct-api](https://c2sp.org/static-ct-api))

## Updating specs

```bash
# PLANTS spec
curl -sL https://davidben.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.txt \
  -o draft-ietf-plants-merkle-tree-certs.txt
rm -rf draft-ietf-plants-merkle-tree-certs/
duvet extract draft-ietf-plants-merkle-tree-certs.txt --out .

# Trust Anchor IDs spec
curl -sL https://tlswg.org/tls-trust-anchor-ids/draft-ietf-tls-trust-anchor-ids.txt \
  -o draft-ietf-tls-trust-anchor-ids.txt
rm -rf draft-ietf-tls-trust-anchor-ids/
duvet extract draft-ietf-tls-trust-anchor-ids.txt --out .

# C2SP specs (from a clone of https://github.com/C2SP/C2SP)
cp /path/to/C2SP/{tlog-tiles,tlog-checkpoint,signed-note,static-ct-api}.md .
for spec in tlog-tiles tlog-checkpoint signed-note static-ct-api; do
  rm -rf "$spec/"
  duvet extract "$spec.md" --format markdown --out .
done
```

Then update the pinned commit hashes above, and fix any broken duvet
annotations in `quic/s2n-quic-mtc/`.

## Generating the compliance report

```bash
duvet report \
  --spec-pattern 'specs/merkle-tree-certs/**/*.toml' \
  --source-pattern 'quic/s2n-quic-mtc/**/*.rs' \
  --require-tests false --no-cargo \
  --html target/compliance/mtc-report.html
```
