# M42 Conversion Plan: Pilot to LOI/MOU to Pre-Seed

Status date: 2026-06-12

## Objective

Convert the $200,000 paid pilot into two signed outcomes without letting either weaken the other:

- **Track A (commercial):** a signed LOI or MOU for the next-phase deployment, presented at the Week 4 executive value board while pilot evidence is at maximum freshness.
- **Track B (strategic investment):** a $2,000,000 pre-seed investment by M42 (or its corporate development / ventures arm), negotiated on a separate paper and a separate clock, de-risked by the same pilot evidence.

The pilot is never contingent on the investment, and the investment is never a condition of pilot success. M42 must be able to say yes to either track independently. Coupling them converts a paid pilot into a disguised fundraise and damages both.

## Two-Track Structure

| Track | Instrument | Owner on M42 side | Decision forum | Earliest introduction | Target signature |
|-------|-----------|-------------------|----------------|----------------------|------------------|
| A: Commercial expansion | Non-binding LOI (`m42-loi-draft.md`) or MOU (`m42-mou-draft.md`) | Pilot sponsor + business development | Executive value board (Week 4) | Week 3 (socialize draft) | Week 4–5 |
| B: Pre-seed investment | Investment memo (`m42-preseed-investment-memo.md`) then term sheet | Corporate development / ventures / investment committee | Separate IC process | After Week 2 evidence room walkthrough | Weeks 6–10 |

## Why M42 Would Do Both

Track A logic: the pilot acceptance bar (100% hybrid evidence coverage, 6/6 negative controls rejected, value-bank scorecard reviewed) maps directly to the LOI's stated preconditions. If the bar is met, the LOI is the natural continuation; if it is not met, the LOI never gets presented and credibility is preserved.

Track B logic: M42 is commercializing Med42 and genomics assets to sovereign buyers who demand independently verifiable evidence. Aethelred is the only layer purpose-built for that evidence model. A $2M pre-seed position gives M42:

- influence over an infrastructure layer its commercial roadmap will depend on,
- anchor-client economics locked before testnet launch repricing,
- the validator-participation option already described in the business case (Section 11) converted from a procurement line into an equity-aligned stake,
- alignment with the UAE sovereign AI agenda using a UAE-domiciled (ADGM-planned) project.

## Conversion Triggers by Pilot Week

| Moment | Conversion action | Output |
|--------|-------------------|--------|
| Sponsor alignment session (pre-start) | Map decision owners for BOTH tracks: who signs an LOI, who sponsors an investment internally. Do not pitch investment yet; only identify the corp-dev contact. | Decision-owner map includes corp-dev names |
| Week 1: sandbox activation | Deliver flawless activation. No conversion talk. Value accumulation only. | Live sandbox validation log |
| Week 2: evidence room walkthrough | After the walkthrough lands, give the sponsor the differentiation dossier (`docs/workload-packs/m42/differentiation-dossier.md`). Ask the sponsor to introduce corporate development "for context on where this platform is going." Send the investment memo only to corp-dev, not to procurement. | Dossier delivered; corp-dev intro made |
| Week 3: assurance challenge session | Socialize the LOI draft with the sponsor 1:1 ("we want the value board to have something concrete to react to"). Capture redlines before the board. Separately, hold the first corp-dev call on the investment memo. | LOI redlines; IC interest signal |
| Week 4: executive value board | Present the value scorecard, then the LOI as the recommended next step. The investment track is mentioned only as "a separate conversation already underway with your corporate development team" — one sentence, no pitch. | LOI signature or dated commitment |
| Weeks 5–10 | Drive Track B to term sheet using the final pilot readout as the diligence packet. The signed LOI is itself an investment de-risking exhibit. | Term sheet for $2M pre-seed |

## The Ask Ladder

Never present a bigger ask before the smaller one beneath it is secured or visibly progressing.

1. Pilot delivered to acceptance bar ($200K, already proposed).
2. LOI/MOU for next-phase deployment (non-binding, Week 4).
3. Next-phase paid deployment contract (binding, post-LOI, separate negotiation).
4. $2M pre-seed term sheet (separate track, corp-dev forum).
5. Validator participation + ecosystem role (post-investment option, already framed in business case Section 11).

## Objection Handling

| Objection | Response | Supporting artifact |
|-----------|----------|---------------------|
| "You are pre-registration; we cannot invest." | Correct — the term sheet is conditioned on ADGM entity registration completing, which is part of the use of funds. The LOI track is unaffected. | Investment memo, milestones section |
| "Why not just buy the service? Why invest?" | Buying gets the service at market terms. Investing gets pre-testnet entry, anchor economics, validator allocation, and roadmap influence over a layer your sovereign sales already need. | Investment memo, strategic rights menu |
| "We could build this internally." | The business case answers this (page 4): an in-house attestation system is M42 attesting to its own work. Independence is the product; a self-built system cannot supply it by definition. | Business case PDF, differentiation dossier |
| "How are you different from [chain X]?" | Walk the differentiation dossier: each claim maps to an artifact M42 inspected in its own pilot, not a whitepaper claim. | Differentiation dossier |
| "The pilot evidence was synthetic." | By design — the no-PHI boundary was a stated control, and the negative controls proved rejection behavior. The next phase introduces approved retrospective data under the LOI. | Negative-control results, sandbox manifest |
| "$2M at what terms?" | Term sheet discussion belongs to corp-dev. The memo proposes a post-money SAFE with a bracketed cap and a strategic side letter; all numbers are open. | Investment memo, structure section |

## Non-Negotiables

- The pilot's acceptance bar, data boundary, and honesty labels are never softened to sweeten conversion. The disclaimers are a trust asset.
- No public announcement, logo use, or "partnership" language without M42 written approval — sovereign health entities are reputationally conservative.
- All binding commitments follow ADGM entity setup and legal review, consistent with the governance notice in the business case.
- Investment discussion never enters the pilot's procurement channel. Different documents, different audience, different meetings.

## Artifacts

Sources of truth (markdown):

- LOI draft: `docs/operations/m42-loi-draft.md`
- MOU draft: `docs/operations/m42-mou-draft.md`
- Investment memo: `docs/operations/m42-preseed-investment-memo.md`
- Differentiation dossier: `docs/workload-packs/m42/differentiation-dossier.md`
- Pilot value structure: `docs/operations/m42-1m-value-pilot-structure.md`
- Delivery plan: `docs/operations/m42-pilot-delivery-plan.md`

Rendered deliverables (regenerate with `make m42-conversion-docs` after editing sources):

- `M42/Aethelred_M42_Differentiation_Dossier_v1_0.pdf` — branded PDF for M42 reviewers (Week 2)
- `M42/Aethelred_M42_Pre_Seed_Investment_Memo_v1_0.pdf` — branded PDF for the corp-dev channel only
- `M42/Aethelred_M42_LOI_Draft_v1_0.docx` — Word draft for counsel redlining; last page is internal, remove before sending
- `M42/Aethelred_M42_MOU_Draft_v1_0.docx` — Word draft for counsel redlining; last page is internal, remove before sending
