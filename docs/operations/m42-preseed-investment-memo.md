# Aethelred Pre-Seed Investment Memo — Prepared for M42 Corporate Development

Status date: 2026-06-12
Document status: INTERNAL DRAFT. Confidential discussion material for M42 corporate development. Not an offer of securities, not investment advice, and not a binding proposal. All figures are illustrative and subject to entity formation, legal review, and definitive documentation. Aethelred is a pre-registration project; ADGM registration of Aethelred Labs and the Aethelred Foundation is planned and is itself part of the use of funds.

Audience note: this memo travels only through the corporate development / ventures channel. It is deliberately separate from the $200,000 pilot, which stands on its own commercial terms and is not conditioned on any investment.

---

## 1. The Ask

A $2,000,000 pre-seed investment in Aethelred by [M42 / its corporate development affiliate], proposed as a post-money SAFE with a valuation cap of [$____] [and a discount of __%], accompanied by a strategic side letter granting M42 the rights described in Section 7.

## 2. What Aethelred Is

Aethelred is a purpose-built Layer 1 for verified AI computation in regulated industries. It is not a general-purpose chain: validators are rewarded for verified, useful AI and scientific work (Proof of Useful Work), every important workload produces a durable evidence object (the Digital Seal binding model hash, policy, TEE attestation, input/output commitments, and zkML proof where applicable), and confidential-compute lanes fix jurisdiction, data class, consent scope, and retention before a job runs. Cryptography is selected to be quantum-resistant (NIST FIPS 203/204/205 alignment) because genomic and clinical evidence must stay verifiable for decades.

The one-sentence version from the business case: a notary and a customs office for AI workloads — it records, provably, that the science was done correctly, in the right place, by the approved model, and lets an outside party check that record without seeing patient data.

## 3. Why This Is Strategic for M42, Not Just Financial

M42 is commercializing two of the region's most valuable regulated AI assets — the Emirati Genome Programme pipelines and the Med42 clinical models — to buyers (sovereign governments, hospital systems, pharma) who increasingly cannot accept black-box infrastructure. The business case quantifies roughly $51M of annual value at stake for M42 by 2028 across internal savings, managed-service profit, evidence subscriptions, and premium uplift.

Every one of those streams depends on an independent verification layer. Independence is the product: an M42-built attestation system would still be M42 attesting to its own work. The layer must be external — which means M42's roadmap acquires a structural dependency on whoever operates that layer.

The investment question is therefore not "is this a good venture bet" but: **does M42 want equity-aligned influence over the verification layer its sovereign sales strategy will depend on, at pre-seed pricing, or does it want to buy that layer later at market terms set by others?**

Specific strategic returns to M42:

- **Anchor economics.** Locked anchor-client pricing on verified compute and evidence subscriptions before testnet launch repricing (side letter, Section 7).
- **Validator stake.** The business case (Section 11) already frames M42 operating validator capacity on approved infrastructure — Proof of Useful Work makes M42's own compute productive and reward-earning. Investment converts that from a procurement option into an equity-aligned role.
- **Roadmap influence.** Priority in workload-lane design for genomics and clinical AI, the two lanes M42 needs first.
- **Sovereign alignment.** A UAE-domiciled (ADGM-planned) verification layer strengthens the national sovereign-AI narrative M42 already leads, rather than importing the trust layer from a foreign hyperscaler.

## 4. Why Now

- **Pre-testnet entry.** The protocol, SDKs (Python/TypeScript), CLI, TEE worker, zkML prover, evidence schema, and enterprise export paths exist and gate in CI today. Public testnet launch is the next repricing event; pre-seed enters before it.
- **The pilot de-risks the thesis at near-zero marginal cost to the IC.** The $200,000 pilot produces, within four weeks, exactly the diligence artifacts an investment committee would otherwise commission: live evidence bundles, negative-control security results, operational gate audits, and a measured economics comparison (Section 5).
- **Category timing.** Confidential computing is a ~$15–17B market growing at 35%+ CAGR; precision medicine ~$130–170B growing low-to-mid teens. The verification layer that lets the second market sell across borders through the first is the gap Aethelred occupies (business case, Section 2).

## 5. How the Pilot De-Risks This Investment

Each standard IC diligence question maps to a pilot artifact M42's own reviewers inspected — not a deck claim.

| IC diligence question | Pilot artifact that answers it |
|----------------------|--------------------------------|
| Does the technology actually produce verifiable evidence? | Per-case hybrid evidence bundles (TEE attestation + zkML proof + Digital Seal), inspected in the Week 2 evidence room walkthrough |
| Does it reject bad inputs, or only demo happy paths? | Week 3 assurance challenge: 6/6 negative controls rejected (missing TEE, missing zkML, wrong model hash, PHI injection, fallback mode, stale-nonce replay) |
| Is the operational maturity real? | Owned go-live gate register, investor-grade gap audit (`m42-pilot-gap-audit`), monitoring/archive stack, CI-enforced readiness workflow |
| Is the team honest about status? | Every artifact is provenance-labeled; drill fixtures are blocked from go-live claims by the strict gate; the business case carries explicit non-claim notices |
| What are the unit economics? | Baseline vs verified run measurement from M42's own workload, latency and cost deltas measured, not asserted |
| Is there commercial pull? | M42's own signed LOI/MOU for next-phase deployment (Track A), plus the value-bank scorecard reviewed by M42's sponsor |

A failed pilot kills this memo. That is intentional: the investment case is conditional on evidence, which is also the product thesis.

## 6. Use of Funds — $2,000,000 over ~18 months

| Allocation | Approx. | Purpose |
|-----------|---------|---------|
| Entity, licensing, governance | 15% | ADGM registration of Aethelred Labs + Foundation, virtual-asset framework counsel, audit-grade governance setup |
| Core engineering | 40% | 3–4 senior protocol/infra engineers: testnet launch, validator onboarding, TEE + zkML hardening on real hardware fleets |
| Security and audits | 20% | Third-party audits of consensus, bridge, and evidence paths (the open audit scopes in the public-testnet readiness gate), continuous fuzzing, red-team of the evidence contract |
| Sovereign deployments | 15% | M42 next-phase delivery capacity, second lighthouse workload (genomics), hosted sandbox infrastructure in-region |
| Operations and runway reserve | 10% | 18-month runway discipline to Series Seed milestones |

## 7. Proposed Structure and Strategic Rights

**Instrument [DECISION POINT]:** post-money SAFE, valuation cap [$____], [discount __% / no discount], pro-rata right at next round. A SAFE keeps legal cost and timeline minimal for both sides and is standard at this stage; a priced round is possible if M42's IC requires it, at higher cost and ~6–8 weeks added timeline.

**Strategic side letter menu** (select with corp-dev; all subject to the independence constraints below):

| Right | Description |
|-------|-------------|
| Anchor pricing | Most-favored pricing on verified compute and evidence subscriptions for [3] years |
| Validator allocation | Reserved validator slot(s) for M42-approved infrastructure at testnet and mainnet, under Proof of Useful Work |
| Workload priority | Genomics and clinical AI lanes prioritized in the protocol roadmap; M42 design input via the joint working group |
| Regional rights | First-offer right to anchor the GCC healthcare deployment of the managed service |
| Information rights | Quarterly investor updates, annual audited financials post-entity-formation |
| Board observer [DECISION POINT] | One non-voting observer seat — recommended over a board seat at pre-seed to preserve speed and future round flexibility |

**Independence constraints (non-negotiable, and in M42's interest):** no single party, including M42, may control consensus or hold rights that compromise the independence of the evidence layer — that independence is precisely what makes M42's own use of the layer credible to its buyers. Validator participation stays within a deliberately diverse set; correctness is enforced by attestation and cryptography, not validator identity.

## 8. Honest Risk Register

| Risk | Status | Mitigation in plan |
|------|--------|--------------------|
| Pre-registration entity | Open | ADGM registration is milestone 1 of use of funds; investment closes conditional on it |
| No public testnet yet | Open | Testnet launch gated by an explicit readiness register (branch, genesis, seeds, audit scopes); funds close the open audit scopes |
| zkML coverage limits | Partial | Proof mode is documented per workload; attestation-backed evidence covers what zkML cannot yet; coverage expands with circuit work |
| Single-founder execution | Open | 40% of funds to senior engineering hires; M42 working group adds review surface |
| Token/regulatory treatment | Open | ADGM virtual-asset framework counsel in use of funds; no token is required for the SAFE itself |
| Concentration on one anchor client | Open | Second lighthouse workload funded; managed-service design is multi-tenant from the start |
| Valuation at pre-seed | Open | Cap bracketed pending comparables discussion; M42's strategic rights are priced into the side letter, not the cap |

## 9. Milestones This Round Funds (to Series Seed)

1. ADGM entity and foundation registered; governance and counsel in place.
2. M42 next-phase deployment delivered under the LOI (live evidence on approved retrospective data).
3. Public testnet launched with independent validators and the open audit scopes closed.
4. Second lighthouse customer (genomics or sovereign health) under paid agreement.
5. Managed-service unit economics validated against the business-case model (~50% gross margin target at scale).

## 10. Process

1. This memo → corp-dev review call (Week 3 of pilot or later).
2. Final pilot readout + value scorecard furnished as the diligence packet (Week 4–5).
3. Term sheet discussion (target Weeks 6–8).
4. Conditions: ADGM registration completing, definitive SAFE + side letter, internal approvals both sides (target Weeks 8–10).

---

*This memo is confidential discussion material prepared by Ramesh Tamilselvan, Founder, Aethelred, Abu Dhabi. It is not an offer to sell or a solicitation of an offer to buy any security. Any investment would be made only under definitive documentation following entity formation and legal review by both parties.*
