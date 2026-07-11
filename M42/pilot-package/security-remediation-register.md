# Security Remediation Register

**Scope:** M42 pilot code paths (`scripts/`, `config/pilots/`, `internal/`, `x/pouw/`, `x/seal/`, `M42/`) and the TypeScript SDK. **Tools:** `govulncheck`, `gitleaks` (with curated config), `npm audit`. **Purpose:** the pre‑diligence "current scan + remediation register" the review calls for.

---

## 1. Summary

| Scan | Result | Real issues |
|---|---|---|
| Go vulnerabilities (`govulncheck`, pilot packages) | **No reachable vulnerabilities** | 0 |
| Secrets (`gitleaks`, curated config) | **No real secrets** — all findings dispositioned | 0 |
| npm dependencies (`npm audit`, SDK) | **0 vulnerabilities after fix** | 0 (1 high remediated) |

**Net:** no committed secrets, no reachable Go vulnerabilities in the pilot paths, and the one high‑severity npm advisory is **remediated** (`form-data` → 4.0.6; SDK typecheck + seal‑contract test re‑verified green).

---

## 2. Secrets scan — findings and dispositions

Raw `gitleaks --no-git` (default rules, scanning on‑disk files including gitignored ones) surfaced 405 candidate findings. Every one was inspected:

| Finding class | Count | What it actually is | Disposition |
|---|---:|---|---|
| `config/pilots/m42/evidence/exports/*.json` entropy hits | ~400 | **Public** cryptographic evidence — commitments, signatures, Merkle roots, attestation quotes. Public by design (they are meant to be independently verified). | Not a secret · allowlisted by path |
| Anvil/Foundry test keys in `scripts/drills/bridge-pause-drill.sh` | 2 | The **publicly documented** Anvil deterministic test private keys (`0xac0974…`, `0x59c6995e…`). Local drill only; no real funds. | **Remediated** — key literals removed; the script now reads env vars and, if unset, derives the local Anvil defaults at runtime from the public Anvil mnemonic via `cast` (no key material in the file). Allowlist entries removed. |
| `verifying_key_hash: "bTQyLX…"` in `m42-sandbox.sh`, `m42-pilot-gap-audit.py` | 2 | Base64 that decodes to the literal placeholder `m42-verifying-key-hash`. | False positive · allowlisted |
| `CRYSTALS-Kyber-1024` in `scripts/__pycache__/*.pyc` | 1 | An algorithm‑name string inside compiled bytecode. The `.pyc` is **not tracked** (`__pycache__/` is gitignored); only seen on disk by `--no-git`. | False positive · gitignored |

A curated `.gitleaks.toml` allowlist (with a justification per entry) was added; `gitleaks --config .gitleaks.toml` now reports **no leaks** across all pilot directories. The earlier explicit tracked‑file sweep (`git ls-files` for password/pem/key material) was also clean, and the operational password files under `config/pilots/m42/secrets/` are gitignored.

---

## 3. Go vulnerabilities

`govulncheck ./internal/attestation/... ./x/pouw/... ./x/seal/...` reports **no vulnerabilities** in reachable code. (govulncheck reports only advisories whose vulnerable symbols are actually called.)

---

## 4. npm dependencies (TypeScript SDK)

| Advisory | Severity | Package | Path | Action |
|---|---|---|---|---|
| GHSA‑hmw2‑7cc7‑3qxx (CRLF injection via unescaped multipart field names) | High | `form-data` (transitive) | build/test tooling — **not** in the pilot's runtime evidence/verification path | **Remediated** — `form-data` → **4.0.6** via `npm audit fix`; only `package-lock.json` changed (no API change) |

**Verification after fix:** `npm audit` → **0 vulnerabilities**; `npm run typecheck` clean; seal‑contract test **13/13**.

---

## 5. Open pre‑diligence items (recommended before M42 engineers inspect)

1. ~~Apply the npm fix and re‑verify the SDK build.~~ **Done** (form-data → 4.0.6; audit clean; typecheck + seal‑contract green).
2. ~~SBOM.~~ **Done** — `M42/pilot-package/sbom/`: npm CycloneDX (53 components) + Go module graph (852). CycloneDX‑gomod to be added in CI.
3. ~~npm license scan.~~ **Done** — all permissive (51 MIT / 1 BSD‑3‑Clause / 1 ISC), **no copyleft**. Go license scan (`go-licenses`) and container scan (`grype`/`trivy`) are documented in the SBOM README with commands (tooling not installed here).
4. ~~Move the Anvil test keys in `bridge-pause-drill.sh`.~~ **Done** — literals removed; env‑referenced with runtime derivation from the public Anvil mnemonic.
5. **Wire `gitleaks --config .gitleaks.toml`, `govulncheck`, and `npm audit` into CI** as scan gates.
6. **Signed release artifacts + reproducible build** for the reviewed pilot tag.
