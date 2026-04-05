# ZeroID — Canonical Source Reference

> **This is not the canonical source.** The canonical source for ZeroID is [`aethelred-foundation/zeroid`](https://github.com/aethelred-foundation/zeroid).

## Quick Reference

| Attribute | Value |
|-----------|-------|
| Canonical Repo | [`aethelred-foundation/zeroid`](https://github.com/aethelred-foundation/zeroid) |
| Pinned SHA | `08b1b82c09e8665b06fe6ff25aec0486f91bfcf5` |
| Pinned Date | 2026-04-05 |
| Homepage | https://zeroid.aethelred.io |
| Status | testnet-preview |

## What This Directory Contains

This directory contains only:
- This reference document
- Compatibility test configuration (when available)
- Integration smoke test fixtures (when available)

## What This Directory Does NOT Contain

Full production source code. That lives in the canonical repo above.

## Protocol Integration Points

- ZK verification precompile for on-chain zero-knowledge proof validation
- Identity registry contract for decentralized identity management
- Cross-chain bridge for portable credential attestations across networks

## For Developers

To work on ZeroID, clone the canonical repo:
```bash
git clone https://github.com/aethelred-foundation/zeroid.git
```

To test protocol compatibility with ZeroID, use the compatibility CI workflow in this repo.
