# Aethelred Whitepaper

## Public Canonical Draft

Version: 1.0  
Date: 2026-03-28  
Prepared by: Aethelred  
Public disclosure posture: governed legal, commercial, and technical disclosures publish only when approved for release.

---

## Important Notice

This whitepaper is a public protocol document prepared for website publication and for review by appointed Company Service Provider and legal counsel. It describes the current technical architecture, governance controls, and disclosure posture of Aethelred.

This document does not state or imply that:

- Aethelred has completed any specific regulatory registration or approval;
- any token sale, exchange listing, or market-maker arrangement has been completed;
- any performance metric is public unless it has been promoted through the benchmark claims register; or
- any statement herein constitutes legal advice, financial advice, or an offer of securities or regulated financial products.

Public performance numbers, launch metrics, legal status, and named counterparties are governed by formal disclosure controls and are published only when approved for disclosure.

---

## Abstract

Aethelred is a blockchain protocol designed for regulated and high-assurance AI workloads. Its core objective is to let enterprises run AI with cryptographic evidence that legal, security, compliance, and audit stakeholders can independently review.

The network combines:

- deterministic blockchain settlement;
- TEE-based confidential execution;
- zkML-based proof verification;
- Digital Seals as portable evidence objects;
- policy-aware data handling and routing; and
- fixed-supply token economics with disclosure-gated release information.

The project is positioned around a simple requirement: in regulated environments, trust must not depend only on vendor assertions. Aethelred is built to let protocol participants prove what ran, where it ran, and how the result was bound to a verifiable record.

External performance numbers publish only from VERIFIED benchmark packs and reviewed claims-register entries.

---

## 1. Why Aethelred Exists

Regulated AI systems face three recurring problems:

- **Execution trust**  
  Buyers and auditors often cannot independently prove that a claimed model, environment, and output actually correspond to the computation that occurred.

- **Confidentiality and sovereignty**  
  Sensitive workloads require controls over where data runs, how it is isolated, and which operators can access it.

- **Evidence portability**  
  Even where logs or attestations exist, they are often fragmented across cloud systems, application logs, and private reports rather than exposed as durable, portable evidence.

Aethelred addresses these problems by combining consensus, attestation, proof verification, and evidence export into one governed protocol surface.

---

## 2. Design Goal

The design goal of Aethelred is not to be a generic high-throughput chain. The goal is to be the fastest platform for regulated enterprises to run AI with mandatory cryptographic evidence.

That goal produces five design constraints:

- confidentiality must be compatible with auditability;
- evidence must be portable and machine-verifiable;
- production paths must fail closed rather than silently degrade to simulation;
- performance claims must be benchmark-governed; and
- legal and commercial claims must follow disclosure state, not pipeline optimism.

---

## 3. Network Overview

Aethelred is built as a protocol stack with five interacting layers:

- **Consensus and state settlement**  
  Deterministic settlement and governance recording.

- **Execution and verification**  
  AI job execution in attested confidential-compute backends with proof verification.

- **Evidence and sealing**  
  Digital Seals that bind inputs, outputs, measurements, and on-chain state.

- **Developer and operator surfaces**  
  SDKs, APIs, tooling, and validator/operator workflows.

- **Disclosure and governance control plane**  
  Claims registers, counterparty disclosure state, legal status tracking, and public-surface drift controls.

This final layer matters because enterprise and regulator trust depends not only on technical controls, but also on disciplined disclosure.

---

## 4. Consensus and Verified Compute

Aethelred uses a Proof-of-Useful-Work design in which consensus and verified AI computation are linked.

At a high level:

1. jobs are routed to the appropriate execution lane;
2. execution occurs inside an approved confidential-compute environment;
3. the governed verification path produces attestation and proof artifacts;
4. evidence is checked against protocol rules; and
5. successful results are sealed and settled on-chain.

This architecture is intended to replace narrative trust with protocol-verifiable evidence.

### 4.1 Lanes and Workload Separation

The protocol roadmap and current scheduler model separate workloads into dedicated lanes so large proof-heavy jobs do not block smaller or faster workloads. This supports:

- fast small-model inference;
- medium enterprise scoring; and
- heavy proof or large-model jobs.

Lane-based scheduling is an architectural control, not a public throughput claim.

---

## 5. Verification Model

The core trust model combines:

- Trusted Execution Environments for confidential execution and measurement; and
- zero-knowledge proof systems for independently checkable verification.

### 5.1 Enterprise Hybrid Path

The enterprise trust posture is centered on a governed hybrid path. In that path:

- execution occurs inside an approved TEE backend;
- the corresponding proof artifact is checked through the supported proof-verification surface; and
- mismatches or incomplete evidence fail closed.

This is the highest-assurance path for regulated workloads.

### 5.2 TEE Coverage

The current public architecture describes support for multiple confidential-compute backends, including:

- Intel SGX;
- AWS Nitro;
- AMD SEV-SNP; and
- NVIDIA confidential-computing paths where applicable.

Public materials describe support posture and controls, but they do not present unverified benchmark superiority claims.

### 5.3 Proof-System Coverage

The protocol surface supports multiple proof-system paths through a unified verification interface. Current public materials may describe proof-system coverage qualitatively, but they do not publish proof-speed or throughput claims unless benchmark verification is complete.

---

## 6. Digital Seals

Digital Seals are the protocol’s portable evidence artifact.

A Digital Seal is intended to bind:

- workload identity;
- model or artifact identity;
- input and output commitments;
- execution evidence;
- verification evidence; and
- settlement context.

This makes the result easier to reuse across enterprise, audit, and interoperability workflows than isolated logs or cloud-specific attestation reports.

---

## 7. Execution Environment

Aethelred is designed around an AI-native execution posture rather than generic smart-contract execution alone.

Public materials currently describe:

- an execution surface with AI-oriented precompiles;
- system contracts for job and seal lifecycle handling;
- confidential-compute backends for execution;
- proof verification surfaces for high-assurance settlement; and
- SDKs and APIs for integration.

The public posture intentionally avoids quoting external performance numbers unless they are benchmark-governed.

---

## 8. Data, Privacy, and Vector Workloads

The protocol is intended for sensitive and regulated data flows. That requires:

- policy-aware treatment of workloads;
- evidence of the environment in which data was handled;
- explicit boundaries between public and confidential state; and
- careful treatment of vector and AI retrieval layers.

A verified Vector Vault data plane anchors namespace metadata and committed vector snapshots on-chain while production embedding and ANN backends run behind attested execution paths.

This design preserves auditability without forcing a full production vector database into consensus state.

---

## 9. Post-Quantum and Cryptographic Posture

Aethelred uses a hybrid cryptographic posture rather than relying on a single primitive.

The public cryptographic posture is:

- ML-DSA-based post-quantum signature support together with classical compatibility where required;
- ML-KEM-768 is the current default transport profile;
- higher-security transport profiles remain available for future governance activation; and
- cryptographic controls are paired with fail-closed production rules rather than soft simulation defaults.

This document does not claim a completed migration away from all classical dependencies across every possible integration surface. It states the current governed transport and signature posture.

---

## 10. Security Model

The security model depends on more than cryptography alone. It includes:

- attestation and measurement governance;
- replay resistance and domain binding;
- verifier registration;
- production-mode rejection of simulated or incomplete evidence;
- operator and release controls; and
- disclosure discipline around what is truly live.

Public security language must match real production rules. If a surface is not yet production-ready, the public documentation should say so or withhold the claim.

---

## 11. Governance and the DLT Framework

The public governance posture is designed to support a DLT Framework that is publicly understandable and reviewable.

At a minimum, the public governance story must cover:

- who is responsible for protocol-level control and change approval;
- how technical change is evaluated and released;
- how risks are assessed, tracked, and mitigated;
- how production monitoring and support are performed; and
- how disclosure is kept consistent across public surfaces.

Aethelred therefore pairs protocol governance with:

- release bundle control;
- benchmark claims governance;
- counterparty disclosure state;
- legal status tracking; and
- truth-pack generation for different audiences.

---

## 12. Token Model Summary

The network uses a fixed supply of 10 billion AETHEL tokens.

The public token posture is:

- fixed supply at genesis;
- zero post-genesis inflation;
- utility roles in staking, fee settlement, slashing, governance, and verified-compute operations;
- burn-based supply reduction mechanisms; and
- launch and commercial metrics withheld until canonical approval for disclosure.

This whitepaper does not publish fundraising, float, valuation, or counterparty claims as protocol facts. Those items belong in approved source packs and disclosure flows.

---

## 13. Benchmark and Claims Discipline

The project maintains a benchmark claims register. The governing rule is straightforward:

- every public performance number must have a reviewed and verified benchmark path before publication.

Accordingly:

- unverified benchmark numbers are not used as public proof;
- planning-model numbers remain internal until measured; and
- benchmark validity is time-bounded and subject to re-verification when code or environment changes.

This discipline is central to enterprise credibility.

---

## 14. Developer Platform

The project’s developer surface includes SDKs, APIs, tools, and local or hosted environments.

Public developer materials must distinguish clearly between:

- local simulation or dev-only paths;
- hosted testnet paths;
- production-grade operator paths.

This distinction matters because developer trust is undermined if public examples silently depend on simulated or insecure fallback behaviour.

---

## 15. Testnet and Operational Readiness

The public testnet posture should be understood as an operational readiness program rather than a marketing claim.

Operational readiness depends on:

- green doctor and health checks;
- hosted topology stability;
- release-bundle integrity;
- operator rehearsal; and
- documented rollback and incident procedures.

Until those items are complete, public materials should describe status honestly rather than implying unconditional production readiness.

---

## 16. Regulatory and Legal Posture

This whitepaper is designed to remain within the current public disclosure boundary.

Public wording currently permitted:

- structured for governed legal and disclosure requirements;
- regulatory and legal publication materials remain in preparation.

Public wording not permitted without evidence:

- completed regulatory registration;
- completed regulatory approval;
- completed regulatory filing; or
- any equivalent wording implying completed registration or regulatory approval.

The project also distinguishes between:

- protocol documentation and disclosure;
- legal characterisation of token activity;
- regulated financial-service activity; and
- activities that may require a licence, authorisation, or licensed third party.

Any activity that requires regulatory authorisation will only be undertaken with the appropriate approval structure in place.

---

## 17. Current Public Disclosure Boundary

The following may be described publicly today:

- architecture and protocol intent;
- current code-backed supply posture;
- current disclosure rules;
- governance controls;
- qualitative verification architecture;
- qualitative security model;
- qualitative developer and operational posture.

The following remain withheld or governed:

- unverified performance numbers;
- launch float and pricing;
- valuation targets;
- exchange and market-maker names before executed status;
- any claim of completed regulatory approval.

---

## 18. Risk Factors

Key public risk categories include:

- technical execution risk;
- benchmark and infrastructure readiness risk;
- developer-path maturity risk;
- legal and regulatory timing risk;
- counterparty execution risk;
- launch timing and disclosure timing risk; and
- adoption risk.

No reader should treat this whitepaper as a guarantee of launch sequence, market outcome, or regulatory result.

---

## 19. Conclusion

Aethelred is built around a practical thesis: regulated AI needs stronger evidence than vendor trust alone.

The protocol’s public design combines:

- deterministic settlement;
- confidential execution;
- proof verification;
- portable evidence in Digital Seals;
- fixed-supply token discipline; and
- governed disclosure controls.

That combination is intended to make Aethelred a credible platform for enterprises that need AI systems to be reviewable by legal, security, compliance, and audit stakeholders.

The public version of that story must remain conservative. Benchmarks, launch metrics, counterparties, and regulatory milestones should become more specific only when the underlying evidence and approvals are in place.

---

## Appendix A - Current Public Statements That Must Remain True

- External performance numbers publish only from VERIFIED benchmark packs and reviewed claims-register entries.
- The network is described with a fixed supply of 10 billion AETHEL tokens.
- ML-KEM-768 is the current default transport profile.
- A verified Vector Vault data plane is the correct public description of the vector architecture.
- Counterparty names remain withheld until executed and approved for disclosure.
- Public regulatory wording remains limited to the current preparation-stage posture.

---

## Disclaimer

This document is provided for informational purposes only. It does not constitute legal advice, financial advice, an offer to sell, a solicitation to buy, or a commitment to regulatory approval, token launch, exchange listing, or commercial execution on any particular timeline. Public statements may change as technical, legal, commercial, and regulatory facts evolve and are approved for disclosure.
