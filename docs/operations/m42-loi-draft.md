# Letter of Intent (Draft) — M42 × Aethelred Next-Phase Deployment

Status date: 2026-06-12
Document status: DRAFT FOR LEGAL REVIEW. This is a working draft prepared by Aethelred for discussion. It is not a legal instrument, has not been reviewed by counsel for either party, and creates no obligations. Bracketed fields are open decision points.

---

## Letter of Intent

**Between:**
[M42 legal entity name], a company incorporated in [Abu Dhabi, UAE] ("M42")

**And:**
[Aethelred Labs Ltd, an entity in formation under the Abu Dhabi Global Market ("ADGM")] ("Aethelred"), represented pending registration by Ramesh Tamilselvan, Founder.

**Date:** [____], 2026

### 1. Purpose

This Letter of Intent ("LOI") records the parties' mutual, non-binding intent to negotiate a next-phase deployment of Aethelred's sovereign verified AI compute and evidence layer for M42 workloads, following the completion of the four-week paid evaluation pilot (the "Pilot") described in the Sovereign Verified AI Compute business case dated June 2026.

### 2. Background

2.1. M42 engaged Aethelred for a $200,000 paid Pilot on the synthetic Med42-compatible evaluation workload `m42-med42-synthetic-eval`, executed in a dedicated sandbox with no access to M42 production systems and no live patient data.

2.2. The Pilot acceptance bar was: (a) 100% hybrid TEE + zkML + Digital Seal evidence coverage for accepted cases; (b) zero accepted single-evidence fallback cases; (c) zero live PHI introduced; (d) six of six negative controls rejected; (e) a completed value-bank scorecard reviewed with the M42 sponsor; (f) a go/no-go recommendation with owners, risks, and next-phase budget logic.

2.3. The Pilot results were presented to the M42 executive value board on [date], with the outcome recorded in the executive readout and value scorecard delivered to M42.

### 3. Intended Next Phase

Subject to definitive agreements, the parties intend to negotiate a next-phase engagement comprising one or more of the following, as selected by M42 at the executive value board:

- [ ] **Option A — Expanded Med42 evaluation:** a larger Med42 evaluation workload under the same evidence contract, with an expanded case volume and M42-approved model checkpoint digests.
- [ ] **Option B — De-identified retrospective clinical AI:** introduction of M42-approved, de-identified retrospective data under a written scope change and M42 governance approval, per the Pilot's data-boundary protocol.
- [ ] **Option C — Genomics workload:** a retrospective genomic variant interpretation or pipeline workload under the sovereign evidence contract.

Indicative next-phase commercial range: [$____ to $____] over [__] months, to be defined in a statement of work.

### 4. Intended Terms of the Next Phase

4.1. **Evidence contract.** Accepted production-track jobs require hybrid TEE attestation, zkML proof evidence, validator signature, and a Digital Seal, consistent with the Pilot's evidence schema. Fallback evidence modes are not accepted deliverables.

4.2. **Data sovereignty.** All workload data remains within [UAE / Abu Dhabi]-approved boundaries. Jurisdiction, data class, consent scope, and retention are fixed in workload policy metadata before execution.

4.3. **No production dependency.** Until definitive agreements state otherwise, no M42 production system shall depend on Aethelred infrastructure.

4.4. **Infrastructure reuse.** The sandbox topology, monitoring, archive, gate register, and evidence tooling delivered during the Pilot remain available to M42 for the next phase.

### 5. Exclusivity and Announcement

5.1. [Optional — DECISION POINT: include or strike] For [90] days from signature, Aethelred will not initiate a competing healthcare-AI assurance pilot with another [UAE-based] healthcare provider, and M42 will negotiate the next phase exclusively with Aethelred for the workloads named in Section 3.

5.2. Neither party will make any public announcement, use the other's name or marks, or characterize the relationship publicly without prior written approval of the other party.

### 6. Strategic Discussions

The parties acknowledge that M42's corporate development function and Aethelred are separately engaged in discussions regarding a potential strategic investment in Aethelred. Those discussions are independent of this LOI, are not a condition of this LOI or of any next-phase engagement, and are governed by their own documentation.

### 7. Non-Binding Effect

Except for Sections 5.2 (announcements), 8 (confidentiality), and 9 (costs), this LOI is non-binding and creates no obligation on either party to negotiate, execute, or perform any agreement. Any binding commitment requires definitive written agreements executed after Aethelred's ADGM entity registration is complete and after each party's internal approvals and legal review.

### 8. Confidentiality

The parties will keep the contents of this LOI, the Pilot artifacts, and all evidence bundles confidential under the [existing NDA dated ____ / confidentiality terms to be agreed], except for disclosures required to advisers and regulators.

### 9. Costs

Each party bears its own costs in connection with this LOI and any subsequent negotiation.

### 10. Governing Framework

This LOI is to be read under the laws of [the Abu Dhabi Global Market]. Any definitive agreements will state their own governing law and dispute resolution terms.

---

**For M42:** ______________________ Name, Title, Date

**For Aethelred:** ______________________ Ramesh Tamilselvan, Founder, Date

---

## Open Decision Points (internal — remove before sending)

| # | Decision | Options | Recommendation |
|---|----------|---------|----------------|
| 1 | Next-phase commercial range in §3 | Leave blank for board / pre-fill an anchor | Pre-fill an anchor range; anchoring at the board is stronger than an open blank |
| 2 | Exclusivity §5.1 | Include mutual 90-day / strike entirely | Include — mutual exclusivity is cheap for Aethelred today and signals seriousness |
| 3 | Which next-phase options (§3) to present pre-checked | A, B, C | Present all three unchecked; let the board choose — choice architecture beats prescription |
| 4 | LOI vs MOU | This LOI / `m42-mou-draft.md` | LOI if the value board lands decisively; MOU if M42 wants partnership framing without a commercial number |
