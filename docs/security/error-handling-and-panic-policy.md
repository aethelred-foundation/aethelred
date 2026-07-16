# Error-Handling and Panic Policy

This document records Aethelred's policy on panics (`panic!`, `.unwrap()`,
`.expect()`) and the triage of the current surface. It exists so that a reviewer
can quickly understand which panic sites are a real availability risk and which
are not.

## Triage of the current surface

A raw count of `.unwrap()`/`panic!` across the repository is misleading because
most of it is in code that **the production network never executes**. The
honest breakdown:

### Deployed product — the Go node (`cmd/aethelredd` + Go sidecars)

The running chain is the Go Cosmos SDK / CometBFT application (see
[ARCHITECTURE §13.1](../ARCHITECTURE.md)). Its `panic` sites in `app/` and
`cmd/` are all one of two **acceptable** patterns:

- **Init-time fail-fast** — e.g. `app/app.go` module-service registration,
  `app/verification_pipeline.go` orchestrator init, `app/readiness.go` readiness
  gates. A misconfigured node *should* refuse to start rather than run degraded.
- **Intentional halt on unrecoverable state corruption** — `app/app.go`
  explicitly panics on detected state corruption (a Cosmos node must halt rather
  than produce divergent state).

There are **no request-path / block-processing panics** that could be triggered
by untrusted input to halt the chain. The deployed node is panic-disciplined.

### Rust workspace — mostly NOT deployed

| Crate | Non-test `.unwrap()` (approx) | Deployed? |
|-------|------------------------------:|-----------|
| `crates/consensus` | 435 | **No** — reference implementation, not linked by any shipped binary |
| `crates/vm` | 204 | **No** — reference |
| `crates/mempool` | 24 | **No** — reference |
| `crates/core` | 203 | Library (used by SDK/tooling) |
| `crates/vault` | 82 | Library |
| `crates/bridge` | 59 | Bridge relayer binary |
| `crates/sandbox` | 44 | Library |

The largest concentrations (`consensus`, `vm`, `mempool` ≈ 663 sites) are in
**reference crates that the production node does not run** (each carries
`#![allow(dead_code)]`). They are not in a reachable production path today.

## Policy

1. **Cryptographic code** (`crates/core/src/crypto`, `crypto/pqc` in Go): no
   `unwrap`/`expect`/`panic` in non-test code. A panic in crypto is a
   correctness/availability defect. Enforced by a clippy guard (below).
2. **Deployed request / block-processing paths**: return errors; never panic on
   untrusted input.
3. **Init / startup**: fail-fast panics are acceptable and preferred over
   running a misconfigured node.
4. **Unrecoverable state corruption**: halting (panic) is the correct behavior.
5. **Reference crates** (`consensus`, `vm`, `mempool`): exempt from the strict
   guard *until they are promoted into the deployed product*. If/when they are
   wired into a shipped binary, they must be brought up to policy first.

## Enforcement

`crates/core/src/crypto/mod.rs` enables `#![warn(clippy::unwrap_used)]` and
`#![warn(clippy::expect_used)]`, with test code exempted via
`crates/core/clippy.toml` (`allow-unwrap-in-tests`, `allow-expect-in-tests`).

As of this writing the guard surfaces **5 non-test sites** in the crypto module
— a small, reviewable backlog. The lint is `warn` (surfaces without breaking the
build); the intent is to review those 5 sites and then tighten the guard to
`deny` so that no new panicking call can be introduced into cryptographic code.
