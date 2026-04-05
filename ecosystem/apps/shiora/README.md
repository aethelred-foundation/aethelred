# Shiora — Canonical Source Reference

> **This is not the canonical source.** The canonical source for Shiora is [`aethelred-foundation/shiora`](https://github.com/aethelred-foundation/shiora).

## Quick Reference

| Attribute | Value |
|-----------|-------|
| Canonical Repo | [`aethelred-foundation/shiora`](https://github.com/aethelred-foundation/shiora) |
| Pinned SHA | `48c0d0dcbf68dc64438a14fcc2c46f58cfc734ce` |
| Pinned Date | 2026-04-05 |
| Homepage | https://app.shiora.health |
| Status | testnet-preview |

## What This Directory Contains

This directory contains only:
- This reference document
- Compatibility test configuration (when available)
- Integration smoke test fixtures (when available)

## What This Directory Does NOT Contain

Full production source code. That lives in the canonical repo above.

## Protocol Integration Points

- ZK attestation circuits for privacy-preserving health credential verification
- FHIR health records integration for standards-compliant medical data handling
- AI inference via TEE for confidential health analytics processing
- DAO governance contracts for community-driven platform decisions

## For Developers

To work on Shiora, clone the canonical repo:
```bash
git clone https://github.com/aethelred-foundation/shiora.git
```

To test protocol compatibility with Shiora, use the compatibility CI workflow in this repo.
