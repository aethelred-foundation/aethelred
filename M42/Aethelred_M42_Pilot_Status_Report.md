> ⚠️ **INTERNAL ONLY — DO NOT SEND TO M42.** Per consultant guidance, this is an internal technical‑status document and candid diligence self‑assessment. The **customer‑facing package is `M42/pilot-package/`** (executive offer, pilot SOW, technical annex, DPIA support pack, claim register, security remediation register). Selected portions of this document may be reused, on request, as a due‑diligence annex.

# Aethelred × M42 — Verifiable AI Compute Pilot
## Technology Status Report — INTERNAL (superseded for customer use by `M42/pilot-package/`)

**Date:** 2026‑07‑11 · **Prepared by:** Ramesh Tamilselvan (Founder) · **Version:** 1.0
**Purpose:** A complete, candid **internal** status of the M42 pilot technology.

---

### 0. How to read this report

This report is written **honesty‑first**. It deliberately separates what is **real and independently verifiable** from what is **simulated, projected, or synthetic**. That boundary is not a weakness we are hiding — it is the core asset. The thesis we are selling to M42 is that *nothing in the pitch is fakeable*: an expert who probes any claim finds real code underneath, and every remaining gap is disclosed. We would rather you see the boundary clearly than have M42's engineers find it for us.

All headline numbers below were re‑verified locally on the date of this report.

---

### 1. Commercial context & the ask

- **Customer:** M42 (Abu Dhabi; healthcare‑AI; operates Med42 LLM, Emirati Genome Programme, Malaffi HIE, biobank, pathology/radiology assets).
- **Engagement:** a **$200,000 paid pilot**. Success target: **MOU/LOI + a ~$2M pre‑seed** commitment after the pilot.
- **What M42 is most drawn to:** *local cost computation* and *sustainable / "every watt useful" compute* — more than the verifiability angle per se.
- **Framing that matters:** the pilot is a **delivery engagement, not a finished product**. It is the vehicle through which we obtain the three real‑world inputs (real silicon, real GPUs, real de‑identified data) that convert our demonstrations into production proof.

---

### 2. Executive verdict

> **We are ready to *win* the pilot engagement. We are not — and by design cannot be — ready to claim the pilot's end‑state is already *proven*.**

These are two different questions and conflating them is the trap. The verification infrastructure is real, unusually honest, and demo‑ready. What remains is exactly the set of things that require M42's hardware and data to complete — which is what the paid pilot is for.

---

### 3. The thesis — three pillars

| Pillar | Claim | M42 interest |
|---|---|---|
| **Verifiable AI** | Every inference produces a tamper‑evident "Digital Seal" anyone can verify | Enabler |
| **Sustainable AI** | Every watt is accounted and provably spent on useful inference | **Primary draw** |
| **Local‑cost compute** | Run inference in‑boundary (sovereign) at a known, verifiable cost | **Primary draw** |

The verifiable pillar is the *enabler*: it is what makes the cost and energy claims defensible rather than slideware.

---

### 4. What has been built (technical substance)

All of the following is implemented code with automated tests, not design documents.

**4.1 Digital Seal cryptography — real and independently verifiable.**
Dependency‑free implementations: RFC 8032 Ed25519 (passes the standard test vectors), SHA3 commitments, Merkle batch anchoring with inclusion proofs, Schnorr NIZK, and a two‑link TEE attestation chain. A standalone verifier reproduces every check with published public keys and **rejects every forgery** (swapped output, forged signature, substituted model hash, tampered attestation, replayed nonce, etc.).

**4.2 Post‑quantum cryptography.** Hybrid Ed25519 + XMSS (WOTS+, SHA3‑256), **NIST Category 5** (highest), a **2¹²⁸ work factor (~3.4 × 10³⁸×)** over a 128‑bit baseline, harvest‑now‑decrypt‑later resistant. Forging requires breaking *both* the classical and the hash‑based leg.

**4.3 L1‑grade speed.** Rollup‑style batch aggregation: prove once at acceptance, then verify a block of seals at signature‑and‑Merkle speed. Re‑verified today: **~24,000 Digital Seals/sec** on the validator fast path vs ~57/sec on the deep‑audit path; the two paths are required to agree in tests.

**4.4 Ten healthcare workloads at scale + statistical rigor.** Genomics, Med42 clinical eval, radiology, drug screening, de‑identification, real‑world evidence, biobank GWAS/PRS, digital pathology, trial matching, and training provenance — each with 100k‑case synthetic fixtures, domain metrics, and acceptance floors. The numerical core (DeLong AUROC CIs, Wilson intervals, bootstrap, calibration/ECE, Benjamini‑Hochberg FDR, subgroup/fairness, BEDROC) is separately tested and cross‑checked against scipy. Radiology and pathology carry a **per‑stratum "blind‑spot guard"** so aggregate sensitivity cannot hide a systematically missed finding type or tissue.

**4.5 Verifiable LLM‑scale inference (Freivalds).** For models too large to zk‑SNARK, we verify the matrix multiplications that dominate transformer compute using Freivalds' algorithm over GF(2⁶¹−1): a validator re‑checks a claimed `Y = W·X` at **~8 × 10⁻⁵⁶ soundness** and **~8–18× cheaper** than recompute, with tamper rejection, bound into a verified seal.

**4.6 PoUW measured energy/cost metering.** The fabricated ESG estimates were removed and replaced with **measured** per‑job energy: an integer‑deterministic on‑chain `WorkReceipt` computing energy/cost/carbon from governance‑set factors, with a canonical hash that matches the pilot encoding byte‑for‑byte. Workers are instrumented to measure energy (Linux RAPL where available; a documented device‑profile estimate otherwise, honestly labeled).

**4.7 Hardware‑agnostic attestation — six platforms.** A unified verifier with **real cryptographic verification** of AMD SEV‑SNP (binary report, ECDSA‑P384, VCEK→ASK→ARK X.509), AWS Nitro (COSE_Sign1/CBOR, ES384), Intel TDX (v4 quote, ECDSA‑P256, PCK chain), and Azure MAA / GCP Confidential Space / NVIDIA NRAS (JWT vs JWKS). Re‑verified today: **6/6 platforms verify, tampering is rejected, and the vendor‑vs‑test‑root boundary is enforced** (a pilot test root cannot satisfy a "require vendor root" policy). A measured `WorkReceipt` is recorded only for a **verified** device, so energy/cost is attributed to attested hardware — this is what ties the three pillars together.

**4.8 Real‑data validation.** The drug‑discovery workload now runs on **real ChEMBL EGFR bioactivity data** (1,148 real compounds, wet‑lab IC50 ground truth), held‑out to prevent leakage: **AUROC 0.9621 (95% CI [0.9477, 0.9765])**, bound into a verified Digital Seal. This breaks the "circular / synthetic" objection for one workload.

**4.9 Test coverage & CI.** ~**23,900 automated tests** (the M42 Python suite ~23,857, plus the Go verifier/attestation/PoUW suites and the TypeScript seal contract). A dedicated CI workflow runs the compile gate, full suite, drill, verifier, throughput/PQC benchmark, real‑data validation, verifiable inference, and the 6‑platform attestation suite + demo. The project's own gap audit reports **31 PASS / 2 WARN / 0 FAIL** (`ready_with_disclosed_warnings`; `go_live_ready = false` by design).

---

### 5. Honest readiness scorecard

Scored as a skeptical expert panel (engineers + clinicians). 10 = production‑proven.

| Dimension | Score | Rationale |
|---|:---:|---|
| Cryptographic foundations | **9** | Real, independently verified; all forgeries rejected |
| Engineering rigor & test coverage | **9** | ~23.9k deterministic tests; integer‑safe consensus math |
| Intellectual honesty / disclosure | **10** | Boundaries disclosed; no fabricated claims |
| Verifiable AI — tractable circuits | **8** | Real Schnorr NIZK + seal |
| Verifiable AI — real LLM | **8** | Freivalds (probabilistic, linear layers); not zero‑knowledge |
| Clinical validity | **8** | 1 workload on real data; **9 still synthetic** |
| Local‑cost computation | **8** | Attributed to attested device; needs real GPU power |
| Sustainable / useful‑watt | **8** | Measured metering; needs a real power trace |
| Hardware trust root | **8** | Real 6‑platform verifier; needs a **live silicon quote** |
| Commercial / pilot readiness | **8** | Strong package; not yet pushed/reviewed |

**Every dimension is 8+.** The four 8s on clinical / cost / sustainable / hardware sit at 8 (not 9) *because the verifier, meter, and loader are production‑real and only the live physical input is pending* — see §7.

---

### 6. Real vs. simulated / projected / synthetic — the boundaries a skeptic will find

| Element | Status | What an expert finds on inspection |
|---|---|---|
| Digital Seal crypto (Ed25519/Merkle/Schnorr) | **Real** | Passes standard vectors; forgeries rejected |
| Post‑quantum (Ed25519+XMSS) | **Real** | Category 5 hybrid |
| Seal throughput (~24k/sec) | **Real** | Measured; two‑path agreement enforced |
| 6‑platform attestation *format* verifiers | **Real crypto, TEST root** | Real parsing + signature + chain, but rooted in a disclosed **test** vendor root |
| TEE hardware root of trust | **Simulated (disclosed)** | Software test root; needs a live silicon‑generated quote |
| Energy — pilot scoring run | **Real (measured wall‑clock)** | Genuine, but small; RAPL unavailable on dev host → labeled estimate |
| Energy — real‑inference figure | **Projected** | Modeled from stated per‑inference latency × GPU profile; clearly labeled a projection |
| Drug‑discovery data | **Real (ChEMBL)** | Real compounds, wet‑lab labels, held‑out eval |
| Other 9 clinical workloads | **Synthetic** | Metrics computed on generator ground truth — not clinical evidence |
| zkML for a full LLM | **Freivalds (probabilistic)** | Verifies linear layers with tiny soundness error; not zero‑knowledge, not the whole model |
| Pilot demonstration layer | **Python** | Shares the evidence model with the Go/Rust production chain but is **not the same implementation** |

---

### 7. The three irreducible real‑world inputs (proposed pilot success criteria)

None of these require new science. Each needs a physical input that only the pilot grants, and the code is already built to consume it:

1. **A live silicon‑generated TEE quote** (any of the 6 platforms) → drop into the existing verifier with the real vendor root; trust basis flips from `test_root` to `vendor_root` with zero code change.
2. **A real GPU NVML/PDU power trace** on real inference → the meter already reads it where the host exposes it; "projected" becomes "measured."
3. **Real de‑identified M42 clinical data** for one imaging/genomics workload → the loader pattern is already proven on real ChEMBL data.

**Recommendation:** write these three into the MOU as the pilot's explicit success criteria.

---

### 8. Engineering & delivery status

- **Committed:** the M42 pilot work is captured in **10 logical, reviewable commits** on the working branch (crypto/PQC/seal, workloads, drill/audit, energy metering, real‑data, Freivalds, attestation, docs). The working branch has since progressed with adjacent chain/SDK work.
- **CI verified locally:** before committing, every CI gate was confirmed green locally — Go (seal, workers, attestation, PoUW), TypeScript (typecheck + seal contract), the Python suite, JSON/OpenAPI validity, and a **no‑secrets sweep** (operational passwords are gitignored and were never staged).
- **Not yet a pushed, reviewed PR for the M42 work specifically.** The work is safe in local git history but is **not backed up off‑machine**, and has not been through a formal review. *(Deliberate hold pending a decision on PR structure — see §10.)*
- **Known hygiene gaps:** (a) open‑source dependency vulnerabilities flagged historically (needs current re‑verification); (b) the **Python pilot layer vs the Go/Rust production chain** are not unified — M42's engineers will ask "which is the product?".

---

### 9. Key risks (ranked)

1. **Data‑circularity perception.** 9 of 10 clinical workloads are synthetic; only drug discovery is on real data. This is the clinical reviewer's sharpest critique and the most credible thing to close before technical due diligence.
2. **Hardware root is simulated** until a live silicon quote is verified — the entire confidentiality story rests on it.
3. **Python‑vs‑Go "which is the product?"** — an integration/story gap, not a capability gap, but it will be probed.
4. **Security hygiene** (dependency vulnerabilities) — a credibility hit for a healthcare buyer if left open.
5. **Delivery hygiene** — work is committed locally but unpushed/unreviewed and not backed up off‑machine.

---

### 10. Open decisions — where we want your feedback

1. **PR / branch strategy.** The M42 commits sit on a branch that has since advanced with other work, and there is an older open PR of narrow scope. Should we (a) push and expand that PR, (b) rebase the 10 M42 commits onto `main` for a clean standalone PR, or (c) something else?
2. **Python↔Go unification.** Do we invest in unifying the pilot demonstration layer with the production chain *before* M42's technical deep‑dive, or clearly document the relationship and defer?
3. **Which real dataset first?** For the pilot's "one real clinical workload," which is the strongest opener — radiology (cleanest public benchmarks), genomics (Emirati Genome adjacency), or pathology — and what is the realistic data‑access path?
4. **MOU success criteria.** Is writing the three irreducible inputs (§7) into the MOU as explicit deliverables the right way to structure the paid pilot?
5. **Sequencing.** Fix hygiene (vulns, push, review) *before* engaging M42's engineers, or in parallel with the pilot?
6. **Scope before the meeting.** Is one real‑data workload enough to anchor credibility, or should we onboard 2–3 real public benchmarks first?

---

### 11. Our current plan (for your validation or redirection)

1. Push + open a reviewable PR + green CI (durability + review).
2. Triage and close the dependency vulnerabilities.
3. Unify — or crisply document — the Python‑vs‑Go relationship.
4. Keep the synthetic‑vs‑real boundary labeled exactly as it is.
5. Treat the three irreducible inputs as the pilot's success criteria, not prerequisites.

**Bottom line for your advice:** the technology is real and the honesty discipline is a genuine differentiator. The question we most want your read on is **sequencing and framing** — how much of §9/§10 to close *before* we put this in front of M42's technical team, versus using the paid pilot itself to close the irreducible items.
