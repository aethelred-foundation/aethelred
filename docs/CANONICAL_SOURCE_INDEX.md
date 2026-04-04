# Canonical Disclosure Source Index

> This index maps each disclosure category to its single canonical source. No public-facing page, website, or communication should contradict the canonical source for its category. Non-canonical documents may contain additional internal detail but must not be treated as authoritative for public disclosure.

| Attribute | Value |
|-----------|-------|
| **Owner** | [Assign — Head of Communications / Compliance] |
| **Version** | 1.0.0 |
| **Status** | Active |
| **Last Updated** | 2026-04-03 |

---

## Source Map

| Disclosure Category | Canonical Source | Classification | Website Copies |
|--------------------|-----------------|--------------------|----------------|
| Protocol architecture, design, and capabilities | `docs/WHITEPAPER.md` | Public Canonical | `frontend/website/org/WHITEPAPER.md`, `frontend/website/io/WHITEPAPER.md` |
| Token economics, supply, distribution, utility | `docs/TOKENOMICS.md` | Public Canonical | — |
| API specification | `docs/API_REFERENCE.md` | Public Reference | — |
| Security posture and audit status | `docs/audits/STATUS.md` | Public Reference | — |
| Threat model | `docs/security/threat-model.md` | Internal Reference | — |
| Validator operations | `docs/VALIDATOR_RUNBOOK.md` | Public Reference | — |
| Testnet operations | `docs/TESTNET_VALIDATOR_RUNBOOK.md` | Public Reference | — |
| Project overview | `README.md` | Public Reference | — |

## Non-Canonical Documents (Internal Reference Only)

These documents contain additional engineering detail and are **not** authoritative for public disclosure:

| Document | Classification | Notes |
|----------|---------------|-------|
| `docs/protocol/tokenomics.md` | Internal Engineering Reference | Contains design-stage parameters not approved for public disclosure |
| `docs/protocol/overview.md` | Internal Technical Reference | Engineering specification; may contain unqualified targets |
| `docs/protocol/consensus.md` | Internal Technical Reference | Engineering specification |
| `docs/pitch-deck/` | Internal / Confidential | Investor materials — subject to NDA and disclosure controls |

## Rules

1. **No public page may contradict its canonical source.** If a website page states a metric, it must match the canonical document or be explicitly qualified as "design target" / "pending" / "subject to governance."

2. **Non-canonical documents may not be referenced from public pages.** If a public page needs information from an internal document, that information must first be promoted to the canonical source through the approval process.

3. **New canonical sources** require: document-control block, legal reviewer assignment, and entry in this index before publication.

4. **Website copies** of canonical documents must be regenerated from the canonical source whenever the canonical source is updated. The version and date must match.
