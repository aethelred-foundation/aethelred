# Cruzible — Canonical Source Reference

> **This is not the canonical source.** The canonical source for Cruzible is [`aethelred-foundation/cruzible`](https://github.com/aethelred-foundation/cruzible).

## Quick Reference

| Attribute | Value |
|-----------|-------|
| Canonical Repo | [`aethelred-foundation/cruzible`](https://github.com/aethelred-foundation/cruzible) |
| Pinned SHA | `9be8e2dff6354c5984bf252f5f6cd0292f78861c` |
| Pinned Date | 2026-04-05 |
| Homepage | https://cruzible.aethelred.io |
| Status | testnet-preview |

## What This Directory Contains

This directory contains only:
- This reference document
- Compatibility test configuration (when available)
- Integration smoke test fixtures (when available)

## What This Directory Does NOT Contain

Full production source code. That lives in the canonical repo above.

## Protocol Integration Points

- CometBFT RPC for real-time block and transaction data
- Staking module integration for validator and delegation dashboards
- Governance module for on-chain proposal display and voting
- Block explorer API for indexed chain state queries

## For Developers

To work on Cruzible, clone the canonical repo:
```bash
git clone https://github.com/aethelred-foundation/cruzible.git
```

To test protocol compatibility with Cruzible, use the compatibility CI workflow in this repo.
