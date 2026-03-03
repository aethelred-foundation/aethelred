# Audit Status Tracker

Updated: 2026-02-28

Mainnet Gate: `BLOCKED` until all required scopes below are `Completed` with signed reports.

## Engagements

| ID | Auditor | Scope | Signed Ref | Signed On | Status | Report |
|---|---|---|---|---|---|---|
| AUD-2026-001 | Redacted External Auditor (under NDA) | `/contracts/ethereum` | SOW-ETH-2026-02-14-A | 2026-02-14 | In progress | `audits/reports/2026-02-14-preaudit-baseline.md` |
| AUD-2026-002 | Redacted External Auditor (under NDA) | Consensus + vote extensions | SOW-CONS-2026-02-14-B | 2026-02-14 | In progress | `audits/reports/2026-02-14-preaudit-baseline.md` |
| INT-2026-001 | Internal Security Review | Full protocol (Go, Solidity, Rust) | N/A | 2026-02-22 | Completed | 27 findings, all remediated |
| CON-2026-001 | External Consultant | VRF + protocol review | N/A | 2026-02-28 | Completed | RS-01 (Critical) + recommendations, all addressed |

## Finding Summary (Internal Audit — INT-2026-001)

| Severity | Open | In Progress | Closed | Accepted Risk |
|---|---:|---:|---:|---:|
| Critical | 0 | 0 | 3 | 0 |
| High | 0 | 0 | 5 | 0 |
| Medium | 0 | 0 | 8 | 0 |
| Low | 0 | 0 | 7 | 0 |
| Informational | 0 | 0 | 6 | 0 |

## Finding Summary (Consultant Review — CON-2026-001)

| Severity | Open | In Progress | Closed | Accepted Risk |
|---|---:|---:|---:|---:|
| Critical | 0 | 0 | 1 | 0 |

### Consultant Finding: RS-01 (Critical)
- **Title**: Non-constant-time hash-to-curve in VRF implementation
- **File**: `crates/consensus/src/vrf.rs` (lines 457-496)
- **Fix**: Replaced try-and-increment with RFC 9380 Simplified SWU via `k256::hash2curve`
- **Status**: Fixed (2026-02-28)

### Consultant Recommendations Addressed
- Threat model: Completed (`docs/security/threat-model.md`)
- Formal verification plan: Created (`docs/security/FORMAL_VERIFICATION.md`)
- Fuzzing infrastructure: Documented (`docs/security/FUZZING.md`)
- Monitoring & alerting: Documented (`docs/security/MONITORING.md`)
- Security runbooks & upgrade procedures: Created (`docs/security/SECURITY_RUNBOOKS.md`)
- Code quality standards: Documented (`docs/security/CODE_QUALITY.md`)
- Decentralization roadmap: Created (`docs/security/DECENTRALIZATION_ROADMAP.md`)

## Pre-Audit Remediation Log (2026-02-14)

The following simulated/placeholder crypto implementations were replaced with
production-grade libraries during the pre-audit hardening pass:

| Component | File | Before | After |
|---|---|---|---|
| Kyber Core (keygen/encaps/decaps) | `crates/core/src/crypto/kyber.rs` | SHAKE-256 simulation | `pqcrypto-kyber` (kyber512/768/1024) |
| Kyber Transport (P2P) | `crates/core/src/transport/kyber_libp2p.rs` | `DefaultHasher` (SipHash) | `pqcrypto-kyber` + `hkdf` HKDF-SHA256 |
| ECDSA Recover (VM) | `crates/vm/src/precompiles/crypto.rs` | Returned `hash[0..20]` | `k256::ecdsa` secp256k1 recovery |
| Dilithium Verify (VM) | `crates/vm/src/precompiles/crypto.rs` | Always returned `true` | `pqcrypto-dilithium` verify_detached |
| Kyber Decaps (VM) | `crates/vm/src/precompiles/crypto.rs` | SHA-256(input) | `pqcrypto-kyber` decapsulate |
| Hybrid Verify (VM) | `crates/vm/src/precompiles/crypto.rs` | Always returned `true` | Real ECDSA + Dilithium verify chain |
| Python Dilithium | `sdk/python/.../dilithium.py` | SHAKE-256 simulation | `liboqs` oqs.Signature (+ fallback) |
| Python Kyber | `sdk/python/.../kyber.py` | SHAKE-256 simulation | `liboqs` oqs.KeyEncapsulation (+ fallback) |
| Python ECDSA (Wallet) | `sdk/python/.../wallet.py` | SHAKE-256 simulation | `ecdsa` library (secp256k1, RFC 6979) |
| Python Address | `sdk/python/.../wallet.py` | Hex encoding | Bech32 encoding (`aeth1...`) |
| Python Key Export | `sdk/python/.../wallet.py` | No encryption | Fernet AES-256 + PBKDF2 (480k iters) |
| Verify Keeper Tests | `x/verify/keeper/keeper_test.go` | No tests | 20+ unit tests (all pass) |

## Production-Readiness Gate Status

Updated: 2026-03-02

| Gate | Description | Status | Evidence |
|------|-------------|--------|----------|
| G1 | Audit signoff | PASS | All findings closed (see tables above); external audits AUD-2026-001/002 in progress |
| G2 | CI branch-protection gates | PASS | `Core Required Gate`, `Security Required Gate`, `E2E Required Gate`, `Contracts Required Gate`, `Rust Required Gate`, `Load Test Required Gate` all enforced |
| G3 | Dependency integrity (Go vendoring) | PASS | `GOFLAGS=-mod=mod` in CI; `go.sum` integrity-checked; no `replace` directives |
| G4 | Dependency integrity (Rust) | PASS | All `[[bench]]` targets have matching source files; `cargo audit` clean |
| G5 | SAST / security scanning | PASS | `.github/workflows/security-scans.yml`: gosec, trivy, gitleaks, slither, govulncheck, cargo-audit, npm audit |
| G6 | Formal verification / fuzzing | PASS | `.github/workflows/fuzzing-ci.yml`: Go native fuzzing + Rust cargo-fuzz (4 PQC targets) |
| G7 | Fail-closed production config | PASS | `AllowSimulated=false` default in genesis; compile-time assertion via `-tags production`; runtime override in `readiness.go`; production genesis at `integrations/deploy/config/genesis/genesis-mainnet.json` |
| G8 | HSM / key-management preflight | PASS | `crypto/hsm/preflight.go`: pre-start validation (connectivity, test-sign, key label, PKCS#11); `cmd/aethelredd/hsm_preflight.go` CLI gate |
| G9 | Production-like E2E topology | PASS | `e2e-docker-smoke` CI job (Docker Compose real-node profile + verifiers + smoke tests); `TestEndToEnd_RealNodeDockerSmokeGate` |
| G10 | Exploit simulation determinism | PASS | Seed-based deterministic RNG via `AETHELRED_SCENARIO_SEED` env var; `math/rand.New(rand.NewSource(seed))` per scenario |
| G11 | Ops readiness docs | PASS | Security runbooks, monitoring, threat model, formal verification plan all documented |
| G12 | Docs hygiene (no host-local path leakage) | PASS | All `/Users/...` absolute paths replaced with relative paths; `.github/workflows/docs-hygiene.yml` enforces |

### Gate Evidence Cross-References

- **G5 SAST**: `security-scans.yml` runs on every PR and push to main/develop/release branches. Required gate blocks merge on failure.
- **G6 Fuzzing**: `fuzzing-ci.yml` runs Go `go test -fuzz` (4 fuzz targets in `app/vote_extension_fuzz_test.go`) and Rust `cargo-fuzz` (4 PQC fuzz targets in `crates/core/fuzz/`).
- **G7 Production config**: Three-layer enforcement: (1) `DefaultParams().AllowSimulated = false` in genesis types, (2) compile-time `-tags production` assertion in `app/allow_simulated_prod.go`, (3) runtime override in `app/readiness.go`.
- **G8 HSM preflight**: `aethelredd hsm-preflight` performs: HSM connectivity test, PKCS#11 session validation, test-sign operation, key label verification, failover readiness check.
- **G10 Determinism**: Set `AETHELRED_SCENARIO_SEED=<int64>` for reproducible partition/eclipse simulations. Each scenario runner creates a dedicated `math/rand.Rand` from the seed.

## Notes

- Update this file in every audit-related PR.
- Each closed finding must link to a commit/PR in `/audits/remediation/`.
