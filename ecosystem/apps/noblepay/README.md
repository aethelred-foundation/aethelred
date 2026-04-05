# NoblePay — Canonical Source Reference

> **This is not the canonical source.** The canonical source for NoblePay is [`aethelred-foundation/noblepay`](https://github.com/aethelred-foundation/noblepay).

## Quick Reference

| Attribute | Value |
|-----------|-------|
| Canonical Repo | [`aethelred-foundation/noblepay`](https://github.com/aethelred-foundation/noblepay) |
| Pinned SHA | `4b92ea8334cce8aa8d07f61f4d5e1e203a614c5a` |
| Pinned Date | 2026-04-05 |
| Homepage | https://app.thenoble.one |
| Status | testnet-preview |

## What This Directory Contains

This directory contains only:
- This reference document
- Compatibility test configuration (when available)
- Integration smoke test fixtures (when available)

## What This Directory Does NOT Contain

Full production source code. That lives in the canonical repo above.

## Protocol Integration Points

- TEE attestation for secure payment processing in trusted execution environments
- Stablecoin settlement lane for high-throughput cross-border transactions
- Compliance engine for regulatory KYC/AML verification
- Go gateway for enterprise API integration

## For Developers

To work on NoblePay, clone the canonical repo:
```bash
git clone https://github.com/aethelred-foundation/noblepay.git
```

To test protocol compatibility with NoblePay, use the compatibility CI workflow in this repo.
