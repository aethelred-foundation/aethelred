# Aethelred Differentiation Dossier — Prepared for M42 Reviewers

Status date: 2026-06-12

## How to Read This Document

Every differentiation claim below is mapped to an artifact M42 inspects during its own pilot. The standard for inclusion is: *if M42 cannot verify the claim from a pilot artifact or the public repository, the claim does not belong in this dossier.* Where a capability is roadmap rather than current, it is labeled as such.

Delivery moment: hand to M42 technical and security reviewers after the Week 2 evidence room walkthrough, when they have just inspected the artifacts this document references.

## The One-Paragraph Difference

General-purpose Layer 1s settle transactions and ask applications to bring their own trust. Aethelred settles **evidence of verified AI computation**: the unit of value on the chain is a Digital Seal binding a model hash, a workload policy (jurisdiction, data class, consent, retention), a hardware TEE attestation, input/output commitments, and a zkML proof where tractable — signed by validators whose work is itself useful computation. For a buyer like M42, the difference is not throughput or fees; it is that *the thing M42's customers and regulators need to inspect is the chain's native object*, not an application-layer convention bolted onto a generic ledger.

## Category 1 — General-Purpose Layer 1s (Ethereum, Solana, Avalanche, generic Cosmos chains)

| Dimension | General-purpose L1 | Aethelred | Pilot artifact that shows it |
|-----------|--------------------|-----------|------------------------------|
| Native object | Token transfer / contract state | Evidence bundle with Digital Seal | `evidence-bundle-<job_id>.json` — schema-validated, per accepted case |
| What validators do | Secure consensus; energy/stake spent on ordering | Proof of Useful Work: rewards for verified AI and scientific computation | Protocol design docs; validator fields in every bundle |
| Confidential data | Public-by-default; confidential workloads need L2s or off-chain systems | Confidential-compute lanes with policy metadata fixed pre-execution | `sandbox.json` data-boundary controls; `workload-pack.json` policy block |
| Evidence rejection | Application's problem | Protocol-level: fallback, wrong-hash, replayed, or single-evidence submissions are rejected | `negative-control-results.json` — 6/6 rejections, run in M42's own pilot |
| Healthcare fit | Generic; HIPAA/UAE-data-class semantics live entirely in app code | Jurisdiction, consent scope, and retention are first-class policy fields | Policy metadata inside each evidence bundle |
| Post-quantum posture | Largely classical cryptography today | PQC-aligned signatures/commitments (NIST FIPS 203/204/205 alignment) for decades-long evidence validity | Crypto suite documented in evidence schema and SDK |

The practical consequence: to give M42 what the pilot gives, a general-purpose L1 would need M42 (or a vendor) to build and operate the TEE orchestration, attestation verification, zkML pipeline, policy engine, evidence schema, and archive as custom application infrastructure — and the result would still be an application-layer convention a counterparty must be persuaded to trust, not a protocol guarantee.

## Category 2 — Confidential-Compute Chains (privacy-focused L1s)

What they offer: TEE-backed private smart contract execution — confidentiality of contract state.

Where they stop short for M42's problem: confidentiality is necessary but not sufficient. M42's buyers need *verifiability of AI execution* — which model version ran, on what data class, in which jurisdiction, with what output commitment — not just that contract state was hidden. Privacy chains hide computation; Aethelred's purpose is to make computation **provable** while data stays protected. The evidence object, the model/circuit registries, the clinical workload policy semantics, and the negative-control rejection behavior are the product, not an application someone could write on a privacy chain.

Pilot artifacts: model registry (`registry/measurements.json` — active model hash binding), circuit registry (`registry/circuits.json`), and the wrong-model-hash negative control showing the chain rejecting a substituted model.

## Category 3 — zkML and Verifiable-Inference Projects

What they offer: proof systems that a specific model produced a specific output — genuinely valuable, and Aethelred uses zkML as one evidence layer.

Where they stop short: zkML alone is a component, not an assurance system. Proof generation is tractable only for certain model sizes/architectures today; there is no data-sovereignty story, no jurisdiction policy, no archive/monitoring/operational layer, and no settlement venue a regulator can query years later. Aethelred's hybrid contract (TEE attestation **plus** zkML **plus** Digital Seal, with single-evidence fallback rejected for accepted paid work) is explicitly designed around zkML's current coverage limits, and says so per workload rather than implying universal proof.

Pilot artifacts: per-job `proof-<job_id>.json` and `attestation-<job_id>.json` sidecars; the documented proof-mode note in the business case (Section 7); the fallback-mode negative control rejection.

## Category 4 — Decentralized Compute Markets

What they offer: cheaper raw GPU/CPU capacity through open markets — part of where Aethelred's cost advantage comes from on the supply side.

Where they stop short: they sell capacity, not assurance. No attestation contract, no policy lanes, no evidence settlement, no healthcare data-class semantics. M42 could rent cheap compute there and still have nothing to show a foreign regulator. Aethelred sits above competitively supplied capacity and adds the verification and evidence layer that makes regulated workloads sellable.

Pilot artifact: baseline vs verified economics in `sandbox-run-summary.json` — the measured overhead M42 pays for evidence, on top of competitively sourced compute.

## Category 5 — Hyperscaler Confidential Computing (the real incumbent)

This is the comparison that matters most in an M42 internal debate, because Azure/GCP/AWS confidential compute is mature and M42 already uses hyperscalers.

| Question an M42 buyer or regulator asks | Hyperscaler confidential compute | Aethelred |
|------------------------------------------|----------------------------------|-----------|
| Can a foreign government verify the run without trusting the seller or its cloud vendor? | Attestation chains terminate in the vendor's and M42's own claims | Evidence settles on an independent ledger; verification requires trusting neither M42 nor a single vendor |
| Is the evidence durable and queryable in 10 years? | Logs and attestations live in vendor accounts under vendor retention | Digital Seals are durable chain objects with archive export (`enterprise_export` query paths) |
| Is pricing inspectable? | Internal allocation, negotiated discounts, opaque | Settlement on a transparent market; cost basis open to inspection |
| Sovereignty narrative | US hyperscaler trust root | UAE-domiciled (ADGM-planned) layer; in-region lanes |
| Sustainability narrative | Datacenter PPA claims | Proof of Useful Work: security spend *is* productive computation |

Honest boundary: hyperscaler confidential compute is excellent infrastructure, and Aethelred TEE lanes can run **on** such hardware. The differentiation is the independent settlement and evidence layer above it — which is exactly the part the hyperscaler cannot supply, because it would be attesting to itself.

## Category 6 — Building It In-House at M42

Covered in the business case (page 4) and repeated here because it recurs in every internal debate: a team of M42's scale could build a verification system, but it would be M42's system, and a counterparty would still be asked to trust M42's attestation of its own work. **Independence is the product; an in-house system cannot supply it by definition.** The same logic is why the investment structure (see corp-dev memo) caps any single party's consensus influence — including M42's.

## Claims We Deliberately Do Not Make

Maintaining these boundaries is part of the differentiation — M42's reviewers will test them.

- No clinical-correctness claim: circuits bind IO, policy, and evidence commitments; they do not prove a free-text answer is clinically right. The clinical evaluation protocol measures that separately.
- No production or live-attestation claim from drill fixtures: provenance labels and the strict go-live gate (`make m42-pilot-go-live`) block that by construction.
- No guaranteed-savings claim: the $1M value architecture is a sponsor-perceived value target; economics are measured per workload against M42's own baseline.
- No universal zkML claim: proof mode is documented per workload.

## Reviewer Checklist

For an M42 reviewer who wants to verify this dossier in one sitting:

1. Open any `evidence-bundle-<job_id>.json` under `config/pilots/m42/evidence/exports` — confirm hybrid evidence fields, policy block, validator fields, `seal_id`.
2. Open `negative-control-results.json` — confirm all six rejection behaviors, including wrong model hash and PHI injection.
3. Open `config/pilots/m42/registry/measurements.json` — confirm the active model hash matches the bundles.
4. Run `make m42-sandbox-preflight` — confirm the package validates from a clean checkout.
5. Ask us which of the above a general-purpose chain, a privacy chain, a zkML library, a compute market, or a hyperscaler provides as a native, independently settled object. That question is the dossier.
