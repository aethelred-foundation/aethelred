# AETHEL Tokenomics Paper

## Public Canonical Draft

Version: 1.1
Date: 2026-04-03
Prepared by: Aethelred
Public disclosure posture: governed legal, commercial, and technical disclosures publish only when approved for release.

### Document Control

| Attribute | Value |
|-----------|-------|
| **Document Owner** | [Assign -- Head of Token Economics] |
| **Legal Reviewer** | [Assign -- Legal Counsel] |
| **CSP Reviewer** | [Assign -- Company Service Provider] |
| **Current Status** | Public Canonical Draft -- Pending Legal Review |
| **Last Approved Date** | 2026-04-03 (engineering and disclosure-owner review) |
| **Next Review Date** | [Upon CSP appointment] |
| **Classification** | Public Canonical -- Approved for Website Publication |

---

## Important Notice

This document is a public utility-token and protocol-economics paper prepared for website publication and for review by appointed Company Service Provider and legal counsel. It is designed to align with the current public disclosure posture of the project.

This document does not state or imply that:

- Aethelred has completed any specific regulatory registration or approval;
- any token sale, exchange listing, or market-maker agreement has been completed;
- any launch pricing, float, or valuation metric has been approved for disclosure; or
- any statement herein constitutes an offer of securities, units in a collective investment arrangement, derivatives, fund interests, or any other regulated financial product.

Any regulated activity requiring a Financial Services Permission, or equivalent approval, will only be conducted by an appropriately authorised entity or after the required permissions are obtained.

---

## 1. Executive Summary

This paper explains the current public token design of AETHEL, the native utility token of the Aethelred protocol. It focuses on:

- token purpose and intended use;
- fixed-supply issuance discipline;
- economic control principles;
- utility flows across staking, fees, governance, and verified compute;
- disclosure governance over launch and commercial information; and
- the current public legal boundary.

The tokenomics design is built around one central principle: the economic layer must reinforce protocol credibility rather than undermine it. That means supply discipline, utility clarity, burn logic, slashing accountability, and disclosure controls all matter together.

### 1.1 Public Metrics At A Glance

| Metric | Current Public Position |
|---|---|
| Native token | `AETHEL` |
| Total supply | `10,000,000,000 AETHEL` |
| Supply model | Fixed at genesis |
| Post-genesis inflation | `0%` |
| Primary token roles | Staking, fees, slashing collateral, governance, verified-compute settlement |
| Launch metrics | Governed and withheld pending approval |

### 1.2 Economic Design Intent

AETHEL is designed to support a protocol whose core purpose is verifiable AI computation. That makes its economic role different from a token whose only job is generalized gas consumption or speculative exchange.

The public token paper is therefore written as an operating model and control document, not as a sales brochure.

---

## 2. Current Public Disclosure Posture

The current public posture is intentionally conservative.

Publicly disclosed today:

- fixed supply: 10,000,000,000 AETHEL;
- post-genesis inflation: 0%;
- utility-first token design;
- fee, burn, staking, slashing, governance, and settlement roles; and
- disclosure controls for launch, counterparties, and regulatory status.

Not publicly disclosed today:

- launch float and circulating supply at token generation event;
- token price, valuation, and fundraising round metrics;
- exchange, market-maker, or liquidity counterparty names;
- any unverified performance or commercial metrics; and
- any statement that implies completed regulatory registration or approval.

### 2.1 Disclosure Classes

| Information class | Current state | Publication rule |
|---|---|---|
| Supply and inflation | Public | Code-backed and canonical |
| Utility roles | Public | Must remain consistent with current protocol design |
| Launch float and price | Withheld | Publish only through approved source pack |
| Counterparty names | Withheld | Executed-only and approval-gated |
| Performance metrics | Withheld | Benchmark-gated |
| Regulatory status | Withheld except preparation-stage wording | Evidence- and legal-approval-gated |

These withheld items publish only after approval through the canonical token source pack and the relevant disclosure process.

---

## 3. Economic Design Principles

The public token design follows a small number of stable principles.

### 3.1 Fixed Supply Discipline

The supply should not expand post-genesis under the current canonical posture.

### 3.2 Utility-First Design

The token is presented as protocol utility, security collateral, and settlement infrastructure rather than as an ownership or revenue-share instrument.

### 3.3 Burn-Compatible Scarcity

Deflationary mechanics may reduce circulating supply over time without requiring inflation elsewhere in the system.

### 3.4 Accountability Through Bonding and Slashing

The economic model should reward correct operation and impose costs on harmful or fraudulent behavior.

### 3.5 Governance Over Disclosure

Economic truth is not whatever appears in a spreadsheet or pitch deck. Public token statements must follow canonical source control and legal/disclosure approval.

---

## 4. Token Nature and Intended Use

AETHEL is designed as a protocol utility token for a network that verifies artificial-intelligence computation with cryptographic evidence.

Its current intended uses are:

- staking and validator participation;
- slashing collateral and security bonding;
- payment of protocol fees;
- governance participation;
- settlement support for verified computation;
- fee burning and supply reduction mechanisms; and
- treasury and ecosystem coordination under governance controls.

AETHEL is not described in this paper as:

- an ownership interest in Aethelred;
- a claim on dividends, profits, or protocol revenue;
- a debt instrument;
- a redemption right against the project team;
- a right to guaranteed appreciation; or
- a promise of exchange or listing access.

### 4.1 Public Utility Matrix

| Utility role | Public description |
|---|---|
| Staking | Economic security and validator participation |
| Slashing collateral | Accountability for downtime, fraud, or harmful behavior |
| Fee settlement | Native unit for protocol fee accounting |
| Governance | Participation in protocol-level decision processes |
| Verified-compute settlement | Payment and settlement support for AI jobs and associated evidence |
| Burn | Supply reduction through fee-based mechanisms |

Final legal characterisation depends on the applicable legal framework, actual launch structure, required licences, and review by counsel and the appointed Company Service Provider.

---

## 5. Supply Architecture and Denomination Model

The current canonical token state is:

- total supply: 10,000,000,000 AETHEL;
- genesis mint model: fixed supply minted at genesis;
- post-genesis inflation: zero; and
- hard supply cap: 10,000,000,000 AETHEL.

The codebase enforces this posture at the protocol level. The canonical emission configuration sets:

- initial inflation basis points: `0`;
- target inflation basis points: `0`; and
- maximum supply cap: genesis supply.

### 5.1 Supply Parameters

| Parameter | Value |
|---|---|
| Total supply | `10,000,000,000 AETHEL` |
| Genesis mint model | Fixed supply minted at genesis |
| Post-genesis inflation | `0%` |
| Hard supply cap | `10,000,000,000 AETHEL` |
| Change boundary | Governance and code change would be required to alter public posture |

### 5.2 Denomination Model

For operational clarity, AETHEL uses multiple denominations across layers:

- Cosmos L1 accounting unit: `uaethel` with 6 decimals;
- EVM and Rust execution environments: 18-decimal representation for compatibility and bridge interoperability.

| Denomination | Meaning | Use |
|---|---|---|
| `AETHEL` | Human-readable unit | Public references and economic summaries |
| `uaethel` | 6-decimal base unit | Cosmos accounting |
| 18-decimal execution form | Compatibility denomination | EVM and compatible execution surfaces |

This is a technical denomination model, not an economic increase in supply.

### 5.3 Supply Change Boundary

Under the current public design:

- total supply can remain constant or decrease through burn mechanics;
- total supply cannot increase beyond the hard cap without a code change and formal governance process; and
- any attempt to publish an inflationary public posture would conflict with the current canonical code and disclosure policy.

---

## 6. Utility Flows in the Protocol

The token’s utility is tied to protocol operations, not merely to narrative positioning.

### 6.1 Staking and Validator Security

Validators and other security-relevant operators use AETHEL as bonded collateral. This aligns network participation with economic accountability.

The token supports:

- validator admission and continued participation;
- slashing for downtime, fraud, or malicious conduct;
- economic weight in selected governance flows; and
- deterrence against invalid verification and governance abuse.

### 6.2 Fee Settlement

AETHEL is the native unit for protocol fee accounting. Fees may reflect:

- base network usage;
- verification pathway requirements;
- hardware and assurance profile;
- jurisdictional or policy-aware routing; and
- urgency or service tier.

### 6.3 Governance

AETHEL participates in the project’s governance design together with non-token governance safeguards. Current public materials describe governance as a control framework, not as a promise of unrestricted tokenholder control over all matters.

### 6.4 Verified Compute Settlement

The network’s purpose is not generic transaction throughput alone. AETHEL supports settlement and policy enforcement around verified AI jobs, Digital Seals, and related protocol services.

### 6.5 Utility Flow Summary

| Flow | Economic effect |
|---|---|
| Staking | Locks capital into protocol security |
| Slashing | Creates downside for harmful behavior |
| Fees | Creates recurring transactional demand |
| Burn | Reduces supply under defined conditions |
| Governance | Aligns token utility with protocol control surfaces |

---

## 7. Validator, Staking, and Security Economics

A protocol token becomes more credible when security participation is tied to explicit economic accountability.

### 7.1 Security Bonding Principle

AETHEL is used as bonded collateral to align validator incentives with network correctness. The public point is the incentive structure, not a speculative yield projection.

### 7.2 Slashing Philosophy

The slashing philosophy is straightforward:

- downtime should have an economic consequence;
- fraud should have a stronger consequence;
- evidence-related or consensus-related abuse should not be economically neutral.

### 7.3 Public Staking Posture

This paper does not publish APY promises or launch-day reward projections. Those depend on network state, governance, and release conditions, and therefore belong in governed operational materials rather than in public token marketing.

### 7.4 Economic Security Matrix

| Security lever | Purpose |
|---|---|
| Bonded stake | Align validator incentives with network health |
| Slashing | Penalize harmful or fraudulent behavior |
| Governance participation | Align protocol control with committed participants |
| Reputation and evidence controls | Encourage valid execution and valid proof handling |

---

## 8. Fee Market and Verified Compute Settlement

The fee market is designed to reflect more than raw transaction inclusion. It is intended to reflect the cost of verified, policy-aware, evidence-bearing computation.

### 8.1 Fee Components

| Fee component | Public description |
|---|---|
| Base network fee | Covers standard network activity |
| Verification premium | Reflects proof or attestation pathway requirements |
| Hardware / assurance factor | Reflects higher-assurance execution conditions |
| Policy-routing factor | Reflects jurisdictional or policy-aware treatment |
| Priority / urgency factor | Reflects service-tier or scheduling requirements |

### 8.2 Settlement Logic

AETHEL functions as the unit through which verified compute is priced and settled. This makes the token economically tied to useful work, not only to generalized block occupancy.

### 8.3 Public Disclosure Rule For Fee Metrics

This paper describes the fee model qualitatively. It does not publish launch fee curves, expected burn volumes, or utilization-linked projections unless and until such figures are reviewed and approved for public disclosure.

---

## 9. Burn and Deflation Mechanisms

The public economic design includes deflationary elements. Under the current design posture:

- the token begins from a fixed supply baseline;
- protocol fees can be partially burned;
- burn mechanisms may scale with utilisation; and
- any burn reduces supply permanently rather than offsetting inflation.

### 9.1 Why Burn Matters In This Design

Burn mechanics are not included as spectacle. They matter because they make demand for protocol usage economically legible in supply terms while preserving the zero-inflation posture.

### 9.2 Burn-Compatible Scarcity

This means deflationary effects can occur without contradicting the fixed-supply model.

### 9.3 Public Burn Posture

Because public launch and usage metrics remain withheld pending canonical release, this paper describes the burn architecture qualitatively rather than publishing speculative demand-driven projections.

| Burn dimension | Current public position |
|---|---|
| Base state | Fixed supply |
| Burn source | Fee-linked |
| Directional effect | Deflationary |
| Quantitative forecast | Withheld pending approved evidence |

---

## 10. Governance, Treasury, and Change Control

The token model is not governed only by narrative. It is tied to:

- code-level supply constraints;
- public disclosure controls;
- claims-register discipline;
- counterparty disclosure state management; and
- legal and regulatory status tracking.

### 10.1 Treasury Role

Treasury references in public materials should be interpreted as governed coordination and operating capacity, not as an unconstrained spend bucket or commercial promise.

### 10.2 Governance Layers

| Control layer | Function |
|---|---|
| Code-level | Hard cap and inflation posture enforcement |
| Governance-level | Controlled parameter and process change |
| Disclosure-level | Approval of public economic claims |
| Legal-level | Alignment with filing, licensing, and activity boundaries |

### 10.3 Change Management

The public token paper is one layer in a wider control system that includes:

- source-of-truth files;
- website drift checks;
- disclosure state rules;
- legal artifact tracking; and
- formal approval gates for future public releases.

---

## 11. Launch, Float, and Commercial Disclosure Controls

The most important public rule is that launch metrics do not publish from draft spreadsheets, pitch materials, or unapproved commercial assumptions.

The following items are withheld until approved for public disclosure:

- token generation event float;
- circulating supply at launch;
- launch price;
- implied or target valuation;
- fundraising totals;
- round pricing and timing;
- counterparty inventory allocations; and
- named exchange or market-maker relationships.

### 11.1 Release Conditions For Commercial Metrics

Public release of these items requires:

1. canonical token source pack completion;
2. disclosure owner approval;
3. consistency with the public whitepaper and website;
4. consistency with legal and regulatory posture; and
5. where relevant, executed agreements rather than pipeline discussions.

### 11.2 Why This Control Exists

This rule exists because economic misinformation damages credibility faster than technical delay. In a regulated context, discipline around what is not yet public is part of the economic design itself.

---

## 12. Counterparty Disclosure Policy

Public counterparty naming is governed by a strict rule:

- counterparties may be named publicly only at `EXECUTED` status.

All earlier states, such as:

- target;
- in discussion;
- term sheet; or
- signed but confidential,

remain withheld from public token materials unless and until approved for disclosure.

### 12.1 Counterparty State Model

| Counterparty state | Public naming allowed? |
|---|---|
| Target | No |
| In discussion | No |
| Term sheet | No |
| Signed but confidential | No unless approved |
| Executed and approved for disclosure | Yes |

This rule exists to prevent the token paper from overstating listings, liquidity support, or institutional relationships.

---

## 13. Public Economic Metrics and Governed Metrics

A sophisticated token paper should distinguish between what is public, what is code-backed, and what is intentionally governed.

### 13.1 Public Today

| Metric type | Status |
|---|---|
| Total supply | Public |
| Inflation posture | Public |
| Utility roles | Public |
| Denomination model | Public |
| Burn directionality | Public |

### 13.2 Governed / Withheld Today

| Metric type | Status |
|---|---|
| Float at launch | Withheld |
| Token price | Withheld |
| Valuation | Withheld |
| Fundraising totals | Withheld |
| Exchange / MM counterparties | Withheld |
| Detailed launch unlock metrics | Withheld |

### 13.3 Why This Separation Is Useful

This separation improves the document in two ways:

- it gives readers a complete picture of the economic model; and
- it makes clear which metrics are intentionally controlled rather than accidentally omitted.

---

## 14. Scenario Framework

A responsible public token paper can discuss economic scenarios without publishing speculative launch numbers.

### 14.1 Scenario Types

| Scenario | Public interpretation |
|---|---|
| Low utilization | Burn impact remains limited; security utility dominates |
| Moderate utilization | Fee settlement and burn both become more economically material |
| High utilization | Verified-compute settlement becomes a more visible demand driver |
| Delayed launch disclosure | Commercial metrics remain governed without changing core token design |

### 14.2 What This Section Is Not

This section is not a price forecast, valuation model, or returns projection. It is a qualitative description of how different protocol usage states may change the relative importance of each economic mechanism.

---

## 15. Interoperability and Settlement Economics

AETHEL’s economic role is not isolated to a single execution environment.

### 15.1 Cross-Environment Consistency

The denomination system and bridge compatibility posture are designed so that the token can move across different execution contexts without changing the underlying economic truth.

### 15.2 Settlement Integrity

Cross-domain settlement should preserve:

- fixed-supply accounting discipline;
- evidence integrity;
- governance control over bridge risk; and
- auditability of token movement.

### 15.3 Institutional Settlement Relevance

For institutional flows, economic credibility requires more than transfer mechanics. It requires confidence that movement, proof, and governance rules remain consistent across environments.

---

## 16. Regulatory and Operating Boundary

This paper is written to stay within the current public legal posture of the project.

Accordingly:

- the project may state that it follows governed legal and disclosure controls;
- the project may state that legal and regulatory publication materials remain in preparation;
- the project must not state that it is already registered, approved, or filed unless supported by evidence;
- the project must distinguish protocol utility from regulated financial-service activities; and
- public materials must remain consistent with the current nature and use of tokens and the relevant disclosure posture.

### 16.1 Permitted Activities Principle

Any token-related activity that constitutes a regulated activity will require the relevant legal analysis and, where necessary, the required authorisation or licensed counterparties.

### 16.2 Operating Principle

The token paper must remain aligned with the real operating perimeter of the project. Legal discipline is part of economic credibility.

---

## 17. Risk Factors

Token-related risk remains material. The main public risk categories are:

- launch timing may change;
- public float and pricing may remain withheld until approval is complete;
- counterparties may not reach executed status on the expected timeline;
- technical milestones may change benchmark, release, or testnet timing;
- regulatory interpretation may evolve;
- protocol usage may be lower or higher than expected, affecting fee and burn behaviour; and
- token utility depends on actual network adoption and operational readiness.

### 17.1 Risk Matrix

| Risk category | Public description |
|---|---|
| Launch timing | Sequence may change as approvals and readiness evolve |
| Commercial disclosure | Some metrics may remain withheld longer than expected |
| Counterparty execution | Planned relationships may not become executable or disclosable |
| Technical readiness | Protocol rollout may affect usage timing |
| Regulatory timing | Legal interpretation or filing sequence may change |
| Adoption | Real network demand may differ from design assumptions |

No holder or participant should rely on public token materials as a guarantee of commercial outcome.

---

## 18. Public Summary

The current public token design can be summarised simply:

- AETHEL has a fixed supply of 10 billion tokens;
- there is zero post-genesis inflation;
- the token is designed for protocol utility, security, settlement, and governance;
- deflationary mechanisms may reduce supply over time;
- launch metrics remain withheld until canonical release; and
- public legal and commercial wording remains tightly governed.

This is the version of tokenomics that is suitable for public website publication while the broader legal, commercial, and filing process remains in preparation.

---

## Appendix A - Current Public Token Facts

| Fact | Current public wording |
|---|---|
| Supply | Fixed at `10,000,000,000 AETHEL` |
| Inflation | `0%` post-genesis |
| Token nature | Utility-first protocol token |
| Core roles | Staking, fees, slashing, governance, verified-compute settlement |
| Launch metrics | Governed and withheld pending approved release |
| Counterparty naming | Executed-only and approval-gated |

---

## Appendix B - Glossary

| Term | Meaning |
|---|---|
| Fixed supply | Supply posture in which no post-genesis inflation is publicly permitted |
| Burn | Permanent token removal linked to protocol logic |
| Staking | Bonding of tokens to support network security |
| Slashing | Economic penalty for harmful or invalid behavior |
| Float | Publicly circulating amount at a given moment |
| Disclosure state | Governance state that determines whether a metric may be published |

---

## 19. Document Control

Document status: Public canonical draft
Version: 1.1
Disclosure state: Public website publication permitted
Regulatory state: legal and regulatory publication materials in preparation
Counterparty naming policy: Executed only
Benchmark policy: Token paper does not publish unverified performance claims

---

## Disclaimer

This paper is provided for informational purposes only. It does not constitute legal advice, financial advice, an offer to sell, a solicitation to buy, or a commitment to launch, list, or distribute tokens on any particular date or at any particular price. Public disclosures may change as legal, regulatory, technical, and commercial facts evolve.
