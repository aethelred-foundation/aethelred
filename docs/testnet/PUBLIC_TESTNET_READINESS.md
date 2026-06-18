# Public Testnet Readiness

**Network:** `aethelred-testnet-1`  
**Status:** `BLOCKED FOR PUBLIC VALIDATOR ONBOARDING`  
**Status Date:** 2026-05-24  
**Canonical Gate:** `make public-testnet-readiness`

This page tracks the difference between an internal testnet rehearsal and a public validator launch. CI green is required, but it is not enough by itself. Public launch also requires real launch artifacts, signed or waived security gates, and a clean validator handoff packet.

---

## Current Position

Aethelred is ready for internal devnet/testnet rehearsal from the current branch after PR review and merge. It is not yet ready for external validator onboarding.

The public testnet gate currently blocks on:

| Blocker | Why It Matters | Required Resolution |
|---|---|---|
| External audit scopes still in progress | Public operators need a signed security posture or an explicit launch waiver | Complete `/contracts/ethereum` and `Consensus + vote extensions` signoff, or approve a signed public-testnet waiver |
| Stale genesis time | Validators must start from a genesis timestamp aligned with the actual launch window | Regenerate `config/genesis/testnet-genesis.json` with the approved launch time |
| Zero bridge contract address | Enabled bridge configuration must not point at the null address | Deploy Sepolia bridge contract or disable bridge for the first public cohort |
| Placeholder peer IDs | Validators need real seed and persistent peer node IDs | Replace `seed-1`, `peer-1`, etc. with real `nodeID@host:port` values |

---

## Cryptographic Posture

Post-quantum cryptography is implemented and on by default — it is no longer a launch blocker:

| Property | Value |
|---|---|
| PQC signatures | Real **ML-DSA-65** (NIST FIPS 204) via Cloudflare circl — no simulated path |
| PQC key exchange | Real **ML-KEM-768** (NIST FIPS 203) via Cloudflare circl |
| Classical curve | **secp256k1** (hybrid with ML-DSA) |
| Default node mode | `hybrid` (composite classical + PQC); selecting a non-real mode is rejected at startup |
| Digital Seal | Validator-quorum hybrid signatures (2/3+ power), verified against registered validator keys |
| Validation | NIST ACVP keyGen known-answer tests pass in CI; the readiness gate asserts `metadata.pqc.mode` is `hybrid`/`production` |

The node reads its PQC mode from `aethelred.pqc.mode` / `AETHELRED_PQC_MODE` and defaults to `hybrid`. Validators register their hybrid public key on-chain via `MsgRegisterValidatorHybridKey` (key derived deterministically from the validator's consensus key).

---

## Readiness Command

Run from the repository root:

```bash
make public-testnet-readiness
```

The command validates:

- Testnet genesis checksum and repo-root checksum path.
- Chain ID, testnet metadata, token symbol, and immutable image tag.
- Genesis time is not stale.
- Bridge configuration is not enabled with a zero contract address.
- Seed and persistent peer entries use real node IDs.
- Post-quantum posture: `metadata.pqc.mode` is `hybrid`/`production` (never `simulated`), backed by Cloudflare circl (real ML-DSA-65 / ML-KEM-768) with a secp256k1 classical curve.
- Testnet runbook and release-candidate docs match the current genesis checksum and image tag.
- Required external audit scopes are complete unless a signed public-testnet waiver is explicitly set.

Use `AETHELRED_PUBLIC_TESTNET_AUDIT_WAIVER=1` only after a signed launch waiver exists and is referenced in the release notes.

---

## Launch Sequence

1. Merge the audit-readiness PR after required review.
2. Cut or update `release/testnet-v1.0` from the reviewed commit.
3. Finalize the genesis in one step with the approved launch time, bridge posture, seeds, peers, and image tag:
   `make finalize-testnet-genesis ARGS="--launch-in 48h --disable-bridge --image-tag <ghcr-tag> --seed <id>@host:26656 --peer <id>@host:26656 ..."`.
   This rewrites the genesis, recomputes `config/genesis/testnet-genesis.sha256`, and syncs the checksum/image references in the runbook and release-candidate doc.
4. Confirm the regenerated `config/genesis/testnet-genesis.sha256` matches the published packet.
5. Confirm public image pull by digest, not only by mutable registry state.
6. Run `make public-testnet-readiness`.
7. Run the full CI and branch-protection suite on the release branch.
8. Complete a clean-room validator walkthrough using only `docs/TESTNET_VALIDATOR_RUNBOOK.md`.
9. Record go/no-go signoff in `docs/operations/testnet-release-candidate.md`.
10. Publish validator onboarding packet only after every launch gate passes.

---

## Launch Packet Contents

Every public validator invite must include:

| Artifact | Required Value |
|---|---|
| Release branch or tag | Frozen branch/tag used for genesis and image build |
| Genesis file | `config/genesis/testnet-genesis.json` |
| Genesis checksum | SHA-256 from `config/genesis/testnet-genesis.sha256` |
| Validator image | Immutable GHCR tag and digest |
| Chain ID | `aethelred-testnet-1` |
| Seeds | Real `nodeID@host:26656` values |
| Persistent peers | Real `nodeID@host:26656` values |
| RPC/API/gRPC | Public endpoints and rate-limit policy |
| Faucet | Public endpoint, cooldown, and limits |
| Explorer | Public endpoint |
| Support | Validator channel, emergency channel, and escalation owner |

The public packet must not contain placeholder keys, zero addresses, unpublished claims, mutable image tags, or stale dates.
