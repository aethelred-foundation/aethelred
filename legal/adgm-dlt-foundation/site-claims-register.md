# Site Claims Register

> This register tracks every numeric, legal-status, and regulatory claim made across the public website. Each claim must have: a canonical evidence source, a qualification status, and a named owner. Claims without evidence must be removed or qualified as "design target."

| Attribute | Value |
|-----------|-------|
| **Owner** | [Assign — Head of Communications / Compliance] |
| **Version** | 1.0.0 |
| **Status** | Active — Requires Ongoing Maintenance |
| **Last Updated** | 2026-04-03 |
| **Last Full Sweep** | 2026-04-03 |

---

## Token Economic Claims

| # | Claim | Pages | Qualification | Evidence Source | Status |
|---|-------|-------|--------------|----------------|--------|
| 1 | 10B fixed token supply | org/token.html, org/investors.html, io/index.html, org/index.html | Stated as design parameter | `docs/TOKENOMICS.md` | OK — code-backed constant |
| 2 | 0% inflation / no tail emissions | org/token.html, org/investors.html | Stated as design parameter | `docs/TOKENOMICS.md` | OK — code-backed |
| 3 | 500,000 AETHEL relayer bond | org/network.html, org/token.html, org/investors.html, io/stablecoin-infrastructure.html | Qualified as "target, subject to governance" on network.html; needs same qualification on other pages | `docs/protocol/tokenomics.md` | **Review** — not all pages qualified |
| 4 | 100,000 AETHEL validator stake | org/nodes.html | Qualified as "design target" | `docs/protocol/tokenomics.md` | OK — qualified |
| 5 | 3-of-5 institutional governance | org/token.html, org/investors.html, io/stablecoin-infrastructure.html | Stated as design parameter | Internal architecture | **Review** — should add "design target" |

## Compliance / Regulatory Status Claims

| # | Claim | Pages | Qualification | Evidence Source | Status |
|---|-------|-------|--------------|----------------|--------|
| 6 | "ADGM DLT Foundation registration is in preparation" | All pages (footer disclaimer) | Correctly qualified | Project status | OK |
| 7 | KYC/AML and OFAC-aware workflows | org/nodes.html, org/network.html, org/governance.html | Qualified as "in preparation" on nodes.html; check other pages | — | **Review** — verify consistency |
| 8 | "No Financial Services Permission held" | org/network.html | Stated in stablecoin disclaimer | — | OK |

## Named Counterparties

| # | Claim | Pages | Qualification | Evidence Source | Status |
|---|-------|-------|--------------|----------------|--------|
| 9 | Circle / CCTP V2 | org/token.html, io/stablecoin-infrastructure.html | Named as technical integration partner | Public Circle documentation | **Review** — confirm disclosure-approved |
| 10 | Counterparty names "withheld" / "gated" | org/token.html, org/investors.html | Correctly gated | — | OK |

## Legal Entity Claims

| # | Claim | Pages | Qualification | Evidence Source | Status |
|---|-------|-------|--------------|----------------|--------|
| 11 | "Aethelred Foundation" in Schema.org JSON-LD | org/investors.html, org/token.html, org/network.html, io/index.html | Used as organization name | — | **Review** — should match registered entity name once established |

## Financial Product Claims

| # | Claim | Pages | Qualification | Evidence Source | Status |
|---|-------|-------|--------------|----------------|--------|
| 12 | Stablecoin settlement lane / routing | org/network.html, org/token.html, io/stablecoin-infrastructure.html | Qualified as "design-stage architecture" on network.html | Internal architecture | **Review** — verify all pages have design-stage qualifier |
| 13 | Mint quotas, outflow throttles, reserve checks | io/stablecoin-infrastructure.html | Described as architecture controls | Internal design | OK — technical description |
| 14 | "No live issuance program" boundary | io/stablecoin-infrastructure.html, org/investors.html | Explicitly negative claim | — | OK |

## Performance Metrics

| # | Claim | Pages | Qualification | Evidence Source | Status |
|---|-------|-------|--------------|----------------|--------|
| 15 | No explicit TPS/latency/throughput claims | — | Performance numbers require benchmark governance | `docs/WHITEPAPER.md` benchmark policy | OK — correctly withheld |

---

## Claims Requiring Immediate Action

| # | Claim | Action | Owner | Deadline |
|---|-------|--------|-------|----------|
| 3 | 500,000 AETHEL bond (unqualified on some pages) | Add "design target, subject to governance" on token.html, investors.html, stablecoin-infrastructure.html | [Assign] | [TBD] |
| 5 | 3-of-5 governance (unqualified) | Add "design target" qualifier | [Assign] | [TBD] |
| 7 | KYC/AML wording inconsistency | Verify "in preparation" wording is consistent across all pages | [Assign] | [TBD] |
| 9 | Circle/CCTP naming | Confirm counterparty disclosure approval or remove name | [Assign] | [TBD] |
| 11 | "Aethelred Foundation" entity name | Confirm matches intended registered entity name | [Assign] | [TBD] |

---

## Maintenance Rules

1. This register must be updated whenever a public page is modified
2. New claims require: evidence source + qualification + owner before publication
3. Full site sweep must be repeated monthly and after any bulk content update
4. Claims marked **Review** must be resolved before CSP/legal handoff
