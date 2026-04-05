# TerraQura — Canonical Source Reference

> **This is not the canonical source.** The canonical source for TerraQura is [`aethelred-foundation/terraqura`](https://github.com/aethelred-foundation/terraqura).

## Quick Reference

| Attribute | Value |
|-----------|-------|
| Canonical Repo | [`aethelred-foundation/terraqura`](https://github.com/aethelred-foundation/terraqura) |
| Pinned SHA | `adba87e32cfec766df4ced5925dee185abf98c12` |
| Pinned Date | 2026-04-05 |
| Homepage | https://app.terraqura.com |
| Status | testnet-preview |

## What This Directory Contains

This directory contains only:
- This reference document
- Compatibility test configuration (when available)
- Integration smoke test fixtures (when available)

## What This Directory Does NOT Contain

Full production source code. That lives in the canonical repo above.

## Protocol Integration Points

- IoT oracle for ingesting real-world sensor data as on-chain Proof-of-Physics attestations
- ERC-1155 carbon credit contracts for tokenized environmental assets
- AMM contracts for carbon credit trading and liquidity pools
- TimescaleDB indexer for time-series environmental data queries

## For Developers

To work on TerraQura, clone the canonical repo:
```bash
git clone https://github.com/aethelred-foundation/terraqura.git
```

To test protocol compatibility with TerraQura, use the compatibility CI workflow in this repo.
