# Aethelred — Claim Register (Diligence Source of Truth)

**Purpose:** one authoritative table of every material claim, its exact scope, the evidence available today, its limitations, and its owner. Every customer‑facing sentence must trace to a row here. Marketing adjectives that are not in this register do not go in front of M42.

**Status key:** `Evidenced` (reproducible today) · `Pilot‑deliverable` (needs an M42 dependency) · `Under review` (needs external specialist sign‑off before it is stated as fact).

---

## 1. Execution provenance (the core proposition)

| Claim (precise wording) | Scope | Evidence today | Limitations | Status | Owner |
|---|---|---|---|---|---|
| A tamper‑evident evidence record binds a workload's model identity, input/output commitments, policy, and attestation into one verifiable artifact ("Digital Seal") | One batch of jobs → one record | Standalone verifier reproduces every check with published keys; all forgeries in the attack matrix rejected | Verifier is a Python reference implementation; production verifier is Go/Rust (see §8) | Evidenced | Eng |
| An M42 engineer can verify a record with a standalone tool, no Aethelred hosted service | Offline verification | `make m42-verify`; adversarial demo (§9) | — | Evidenced | Eng |
| Evidence defaults to an **M42‑controlled store**; shared‑ledger anchoring is optional and carries **only batch roots, no patient metadata** | Deployment posture | Design; batch‑root anchoring implemented | Public anchoring not enabled by default | Evidenced (posture) | Eng |

> **Wording rule:** say *tamper‑evident evidence record*, not "on‑chain WorkReceipt", in customer materials.

---

## 2. Post‑quantum signature path

| Item | Precise statement |
|---|---|
| **What it is** | A hybrid signature path (classical Ed25519 **+** hash‑based XMSS) implemented for **long‑term authenticity and integrity** of the audit trail. |
| **Signing granularity** | One hybrid signature over **one batch root per batch** — **not** per receipt. This keeps signature‑capacity demands low. |
| **Current key** | Demo key is XMSS **height‑10 → 1,024 batch signatures** per key. |
| **Production requirement** | XMSS is **stateful**; production needs a documented **key‑rotation / multi‑tree scheme**, state persistence, crash/rollback protection, concurrency control, and hardware key management — **under external cryptographic and key‑management review**. |
| **Do NOT say** | "2¹²⁸ work factor (~3.4 × 10³⁸× over a 128‑bit baseline)" (conflates magnitude with a multiple), or "harvest‑now‑decrypt‑later resistant" (that term is about confidentiality; this is a **signature** integrity benefit). |
| **Customer wording** | "A hybrid post‑quantum signature path has been implemented for long‑lived audit integrity and is undergoing external cryptographic and operational key‑management review." |
| **Status** | Implemented · **Under review** |

---

## 3. Verification of linear‑algebra operations (Freivalds)

| Item | Precise statement |
|---|---|
| **Rename** | "Probabilistic verification of selected transformer **linear‑algebra operations**" — **not** "verifiable LLM inference". |
| **Covers** | The claim `Y = W·X` for committed `W`, `X`, `Y` over a prime field. |
| **Does NOT cover** | Nonlinearities (softmax/activations/normalization), quantization, tokenization/preprocessing, model loading, control flow, or end‑to‑end semantic correctness. |
| **Challenge protocol (hardened)** | Challenges are derived by **Fiat‑Shamir from a commitment to (W, X, Y) plus a verifier nonce** — commit‑then‑challenge. The prover must commit the output before the challenge exists; the nonce prevents precomputation and binds freshness; the derivation is domain‑separated. *(Implemented this cycle; replaced a fixed demo seed.)* |
| **Soundness** | ≤ p^(−rounds); ≈ **8 × 10⁻⁵⁶ at 3 rounds** — valid **only under the stated protocol assumptions**. |
| **Binding to the seal** | W/X/Y commitments and the challenge nonce are bound into the evidence record so a valid linear‑algebra proof cannot be re‑attached to a different inference. |
| **Status** | Evidenced (as scoped) |

---

## 4. Hardware attestation

| Item | Precise statement |
|---|---|
| **Headline** | "Attestation **adapters** have been implemented for **six ecosystems** (AMD SEV‑SNP, AWS Nitro, Intel TDX, Azure MAA, GCP Confidential Space, NVIDIA); production validation on **live vendor collateral** is a pilot deliverable." |
| **Implemented today** | Real format parsing + signature verification + X.509/JWT chain checks against a **disclosed test root**. Tamper, untrusted‑root, and binding‑mismatch cases rejected; a test root **cannot** satisfy a `require‑vendor‑root` policy. |
| **Trust‑type nuance** | Direct hardware‑quote verification (AMD/Intel) is **not** identical to trusting a JWT issuer (Azure/GCP/NVIDIA); the latter also requires explicit issuer‑policy evaluation. |
| **Production acceptance protocol (must all be present)** | nonce/freshness · certificate‑chain + collateral validation · revocation status · minimum TCB/security‑version policy · debug‑mode rejection · workload/container measurement policy · **binding of the attested key to the seal signing key** · clock‑skew/expiry handling · documented failure policy · replay protection (stale quote for a different workload). |
| **Do NOT say** | "zero code change" to go live — configuration, collateral handling, vendor‑policy interpretation, and operational integration are real work. |
| **Status** | Adapters Evidenced · live‑collateral validation **Pilot‑deliverable** |

---

## 5. Energy & carbon accounting

| Measurement level | Definition | Status |
|---|---|---|
| L1 — Estimated device energy | device‑profile (TDP × utilization × time) | Available |
| L2 — Measured accelerator energy | on‑device meter (e.g. NVML/RAPL) | **Pilot‑deliverable** |
| L3 — Measured server/node energy | node telemetry | **Pilot‑deliverable** |
| L4 — Facility‑attributable energy | node × agreed PUE boundary, reconciled to a PDU/ground truth | **Pilot‑deliverable** |

| Item | Precise statement |
|---|---|
| **Do NOT say** | "every watt is useful." |
| **Customer wording** | "Auditable **job‑attributable** compute energy within a defined measurement boundary." Today's figure is measured wall‑clock × a documented device profile (L1); the real‑inference figure is a **projection** until L2–L4 are reconciled against a ground‑truth instrument within a jointly defined tolerance. |
| **Carbon** | State the emission‑factor **source, geography, timestamp**, and whether **location‑based or market‑based**. Governance‑set factors must be **auditable** (who can change them; how historical calculations stay reproducible). |
| **Status** | L1 Evidenced · L2–L4 Pilot‑deliverable |

---

## 6. Clinical / scientific validity

| Item | Precise statement |
|---|---|
| **Synthetic workloads (9 of 10)** | Demonstrate **engineering scalability, metric correctness, pipeline behavior, and negative‑test handling** — **not** clinical validity. Never label these "clinical validity". |
| **ChEMBL EGFR result** | Real compounds, wet‑lab IC50 labels, held‑out evaluation: AUROC 0.9621 (95% CI [0.9477, 0.9765]). **Must disclose:** split type (**currently a random split** — scaffold/temporal split is pending), leakage controls, compound deduplication, class prevalence, calibration, comparator models, and whether any hyperparameters saw the test cohort. |
| **Do NOT lead with the AUROC** | until the **split protocol survives medicinal‑chemistry specialist review** (a random split can be materially easier than scaffold/temporal). |
| **Clinical boundary** | No claim of clinical efficacy unless a separate clinician‑approved validation protocol is completed. |
| **Status** | ChEMBL Evidenced (as scoped) · scaffold/temporal split **Under review** |

---

## 7. Verification throughput

| Item | Precise statement |
|---|---|
| **Do NOT say** | "L1‑grade speed" (blockchain framing is not meaningful to a healthcare buyer). |
| **Customer wording** | Report reproducible **verification throughput** with the **benchmark hardware configuration** and **end‑to‑end overhead**. Current local benchmark: fast‑path record verification ≈ 24k records/sec; deep‑audit path ≈ 57/sec (single dev machine; configuration to be published). |
| **Status** | Evidenced (methodology to be published with hardware spec) |

---

## 8. Engineering assurance (trust argument)

| Item | Precise statement |
|---|---|
| **Custom crypto** | "Dependency‑free implementations" can **alarm** an enterprise security reviewer. Desired progression: standard primitive → vetted library / controlled module → **published test vectors** → fuzzing + negative testing → **independent review** → operational key‑management design. |
| **Test count** | "~23,900 tests" is **not decision‑grade** alone. Needed: coverage by critical component, threat‑model coverage, mutation/fault‑injection, fuzzing, dependency + license + secrets scanning, reproducible build, **signed artifacts**, independent‑review findings. |
| **Two stacks** | The demonstration layer (Python) and production chain (Go/Rust) are **not the same implementation**. They must share **one canonical evidence schema + one published test‑vector set**, and the production verifier must check demo‑generated artifacts. See the architecture‑truth diagram in the technical annex. |
| **Status** | Progression defined · items are pre‑diligence work |

---

## 9. Adversarial rejection (pre‑agreed attack matrix)

The following attacks are demonstrated to be rejected by the verifier (`make m42-adversarial`), to be re‑run **by an M42 engineer** during the pilot:

substituted model · altered output · forged signature · forged inclusion proof · replayed nonce · tampered attestation / untrusted root · binding mismatch (attestation for a different workload) · modified cost/energy factor.

**Status:** Evidenced (demo) · re‑run by M42 is a Phase‑0/1 gate.
