# Reconciling `release/chain-production-hardening` onto the salvage release line

**Status:** blocked on architecture decisions. Not a merge conflict in the
ordinary sense — the two branches contain independent solutions to the same
problems, and picking between them is a design call, not a resolution.

## Situation

Two divergent lines, both branched from `main`, neither containing the other:

| line | commits | date | character |
| --- | --- | --- | --- |
| `salvage/general-purpose-from-sdk-export-pqc` | 93 | 2026-08-08 | the release lineage; contains `release/public-testnet-pqc` and `release/public-testnet-application-bundle-2026-07-31` |
| `release/chain-production-hardening` | 5 | 2026-07-30 | PoUW consensus, PQC production crypto, vote extensions, Groth16 pairing |

Each merges cleanly into `main` alone. Together they conflict in 24 files,
roughly 100 hunks, concentrated in consensus and cryptography.

`ci: stabilize SDK toolchain compatibility` has already been reapplied on this
branch — a one-hunk conflict where the salvage side already carried the
`cargo-audit 0.22.1` pin and the hardening side added the comment explaining
why. Both were kept.

The remaining four commits are blocked.

## Two defects that any naive resolution introduces

Both compile. Both pass tests. Neither is visible in a diff review that treats
this as a routine merge.

### 1. KV-store key prefix collision on `0x11`

`x/pouw/types/keys.go` assigns the same store prefix to different record types:

| byte | salvage | hardening |
| --- | --- | --- |
| `0x11` | `WorkReceiptKeyPrefix` | `LastFinalizedBlockKey` |
| `0x12` | `EnergyAggregateKeyPrefix` | — |
| `0x13` | `EnergyParamsKey` | — |
| `0x14` | `AttestationSummaryKeyPrefix` | — |
| `0x15` | `ValidatorHybridKeyKeyPrefix` | — |
| `0x16` | `SealQuorumSignatureKeyPrefix` | — |

Keeping both declarations puts two unrelated record types under one prefix.
Work receipts and finalized-block records would overwrite and mis-decode each
other: state corruption, and on a live chain, consensus divergence between
nodes that wrote in different orders. The compiler cannot see it, and no test
that exercises only one of the two record types will catch it.

**Resolution:** reassign `LastFinalizedBlockKey` to `0x17`, which is free on
both sides. This is a state-schema change and must be recorded as one — any
chain that has already written under the hardening branch's `0x11` needs a
migration rather than a recompile.

### 2. PQC default mode silently drops to simulated

`app/pqc.go`, the default when `PQC_MODE` is unset:

- salvage: `mode = "hybrid"` — composite classical + PQC signatures required.
- hardening: `mode = defaultPQCMode`, a build-tag constant:
  - `app/pqc_default_production.go` -> `"production"`
  - `app/pqc_default_nonproduction.go` -> `"simulated"`

Both branches share an identical `switch` accepting `hybrid`, `production`,
`simulated` and their aliases, so the *only* difference is the default.

Taking the hardening line means every build without the production tag defaults
to **simulated** cryptography where it previously defaulted to **hybrid**. That
is the configuration devnet and testnet operators run. A security-relevant
downgrade that compiles clean and passes the test suite.

**Resolution:** decide deliberately. Keeping the build-tag mechanism while
setting the non-production default to `"hybrid"` preserves both intentions —
hardening wanted the default to follow build provenance; salvage wanted the
default never to be weaker than composite. They are only in conflict because
`simulated` was chosen as the non-production value.

## Subsystems where both branches solved the same problem differently

These need a decision on which architecture wins before any line-level
resolution is meaningful.

| file | hunks | the disagreement |
| --- | --- | --- |
| `x/pouw/keeper/keeper.go` | 4 | Both fix seal-ID determinism across validators. Salvage overrides the wall-clock timestamp with block time and regenerates the ID; hardening introduces `NewDigitalSealForJobAtBlockTime`. Same bug, incompatible APIs. |
| `app/app.go` | 9 | Different store-mounting strategies. Salvage mounts only stores whose modules are wired and seeds empty ones with a marker in `InitChainer` (empty mounted IAVL stores cannot be loaded by version under iavl v1.x); hardening mounts `authzkeeper.StoreKey` and a `legacyCosmosCrisisStoreKey`. |
| `crypto/pqc/circl_integration.go` | 8 | Different meanings for `PQCMode`. Salvage: mode is signature *policy*, orthogonal to whether the crypto is real. Hardening: without `-tags=pqc_circl`, production and hybrid *fail closed*. |
| `x/pouw/keeper/consensus.go` | 7 | Different verification architectures, visible in the imports: `sealtypes` versus `verifytee`. |
| `app/vote_extension.go`, `app/extend_vote_assignments.go` | 5 | Vote-extension wire format and assignment. |
| `x/verify/groth16/bn254_pairing.go`, `x/verify/orchestrator.go` | 4 | Pairing and orchestration. |

Mechanical, resolvable without a design call: `go.sum` (38 hunks, dependency
union), `go.mod` (5), `Dockerfile`, `Makefile`, `.dockerignore`,
`.gitleaks.toml`, `.github/workflows/docker-build.yml`,
`crypto/pqc/dilithium.go`, `crypto/pqc/kyber.go`, `x/pouw/module.go`,
`x/seal/keeper/msg_server.go`, `x/verify/groth16/verifier_test.go`,
`cmd/aethelredd/cmd/root.go`.

## Recommended sequence

1. Land `salvage/...` on `main` (PR #170). Done independently of this.
2. Decide the six subsystem questions above. They are design calls and should
   be made by whoever owns consensus and the PQC policy, not resolved from the
   diff.
3. Reapply the four remaining hardening commits against those decisions, with
   `LastFinalizedBlockKey` moved to `0x17` and the non-production PQC default
   set explicitly rather than inherited.
4. Verify on a running devnet, not only by `go build`. Both defects above pass
   compilation, and the key-prefix collision only manifests once two record
   types coexist in the same store.
