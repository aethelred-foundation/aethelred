# Aethelred Strict Production-Readiness Gap Checklist

Date: 2026-03-02  
Scope: Current local workspace + latest local test artifacts

Scoring model:
- Each gate is weighted.
- `PASS` earns full gate weight.
- `FAIL` earns 0.
- Overall score = earned / 100.

| Gate ID | Gate | Weight | Status | Score | Evidence |
|---|---|---:|---|---:|---|
| G1 | External independent audit signoff complete for required scopes | 15 | FAIL | 0 | `docs/audits/STATUS.md` shows `Mainnet Gate: BLOCKED`; required scopes still `In progress` |
| G2 | Branch-protection required gates demonstrably green for this revision | 15 | FAIL | 0 | Required checks include Audit/Core/Contracts/Rust/Security/Sandbox/Load/E2E/Docker; no full green proof bundle for this revision |
| G3 | Reproducible dependency state (vendor/lock integrity) | 10 | FAIL | 0 | Go vendoring inconsistent (`go.mod` vs `vendor/modules.txt`) |
| G4 | Build manifest integrity across repos/tools | 8 | FAIL | 0 | Rust testnet manifest references missing bench target (`faucet_bench`) |
| G5 | Security scan gate (SAST, vuln, secrets, static analysis) clean for this revision | 8 | FAIL | 0 | Security gate workflow exists, but no current run evidence proving pass on this revision |
| G6 | Formal verification + fuzzing obligations enforced pre-mainnet | 8 | FAIL | 0 | Formal/Fuzzing docs exist, but workflow scan shows `NO_FORMAL_WORKFLOW_MATCHES` for formal tools in `.github/workflows` |
| G7 | Fail-closed production config (simulation disabled) is verifiable in deploy genesis/config | 8 | FAIL | 0 | Gating plan requires `AllowSimulated=false`, but checked genesis artifacts report `NO_ALLOW_SIMULATED_FIELD` and expected `deploy/config/genesis` dir is missing |
| G8 | Production key-management/HSM controls validated in executable preflight | 8 | FAIL | 0 | HSM policy says mandatory for mainnet; no executable attestation/preflight proof artifact provided |
| G9 | E2E network validation on production-like topology | 8 | FAIL | 0 | E2E smoke passed on local mock/devtools stack (`aethelred-local-devtools-1`), not production-like validator topology |
| G10 | Dynamic exploit resilience stability (repeatable under adversarial scenarios) | 6 | FAIL | 0 | Two exploit-sim runs conflict materially (one degraded, one all A+) indicating non-stable confidence |
| G11 | Ops readiness docs (monitoring + incident runbooks) exist and are current | 8 | PASS | 8 | Security runbooks and monitoring docs are active and recently updated |
| G12 | Docs hygiene and operator usability (no host-local path leakage) | 6 | FAIL | 0 | Large set of `/Users/...` absolute path leaks in public docs |

## Overall
- Passed gates: 1 / 12
- Failed gates: 11 / 12
- **Production readiness score: 8 / 100**
- **Verdict: NOT PRODUCTION-READY**

## Section Ratings

| Section | Gates | Score |
|---|---|---:|
| Audit & Governance Assurance | G1-G2 | 0 / 30 |
| Build & Dependency Integrity | G3-G4 | 0 / 18 |
| Security Verification Program | G5-G6 | 0 / 16 |
| Runtime Hardening & Key Management | G7-G8 | 0 / 16 |
| Resilience & Network Validation | G9-G10 | 0 / 14 |
| Operations & Documentation | G11-G12 | 8 / 14 |

## Most critical blockers to clear first
1. Complete and sign required external audits (`/contracts/ethereum`, `Consensus + vote extensions`) and satisfy audit signoff gate.
2. Repair reproducibility/build integrity failures (Go vendoring drift and Rust testnet manifest bench target).
3. Produce deterministic, repeatable exploit resilience evidence on production-like multi-validator topology.
4. Prove all required CI gates green on the exact release candidate commit.
5. Remove documentation path leakage and tighten release-operability proofs.
