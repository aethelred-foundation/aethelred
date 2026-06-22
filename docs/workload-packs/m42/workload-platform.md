# M42 Pilot Workload Platform

Status date: 2026-06-12

## What This Is

The M42 paid pilot is not a single fixed demo. It is a workload platform that
runs any of **ten** M42 workloads, each with domain-correct synthetic data,
genuinely computed success metrics, its own model and circuit identity, and
per-workload hybrid evidence (TEE attestation + zkML proof + Digital Seal).

M42 selects one workload to drive the four-week paid execution clock. All ten
are built, registered, and demonstrable so the selection is an informed sponsor
decision, not a constraint of the tooling.

The ten cover both M42's **model/clinical** surface (the four business-case
candidate workloads) and M42's **data, diagnostics, trials, and governance**
surface (the assets that most need an independent verification layer to sell or
license across borders).

## The Ten Workloads

### Tier 1 — Model and clinical AI (business-case Exhibit 9)

| Workload | M42 asset | Unit | Primary metric | Why it is a good first pilot |
|----------|-----------|------|----------------|------------------------------|
| Genomic variant interpretation | Emirati Genome Programme | variant | pathogenic recall | High volume, repeatable, clear baseline |
| Med42 evaluation / fine-tuning | Med42 LLM | evaluation case | clinical factuality | Strategic AI asset, measurable benchmarks |
| Retrospective radiology AI | imaging programs | study | AUROC | Clinically relevant, historical data |
| Drug-discovery screening | AI Life Sciences | compound | enrichment factor at 1% | Compute heavy, commercially valuable |

### Tier 2 — Data, diagnostics, trials, and governance (the cross-border unlock)

| Workload | M42 asset | Unit | Primary metric | Why it matters commercially |
|----------|-----------|------|----------------|------------------------------|
| De-identification & data-egress attestation | Malaffi, BioBank, genome data | record | PHI recall | The enabling control: unlocks every cross-border data sale by proving safe egress |
| Malaffi population-health & RWE | ADHDS / Malaffi HIE (3.5M records) | cohort query | count relative error | Monetizes the flagship data asset: regulatory-grade real-world evidence for pharma and governments |
| Biobank GWAS & polygenic risk scores | Emirati Genome Programme (700K genomes) | association test | PRS AUC | Turns the genome programme into pharma-grade association evidence |
| Digital pathology AI | National Reference Laboratory | slide | slide AUROC | A diagnostics service M42 already runs (prostate-cancer AI pathology) |
| Clinical-trial matching & synthetic control arms | IROS | candidate | matching sensitivity | Auditable eligibility and balanced control arms for multi-site and pharma trials |
| Med42 training / fine-tuning provenance | Med42 + Core42/Cerebras | training shard | approved-data coverage | Lets M42 license Med42 internationally with provable training-data provenance and IP defense |

The active workload (Med42) binds the canonical evidence path and the CI gate.
The others run into namespaced evidence directories under
`config/pilots/m42/evidence/workloads/<id>/`.

## Statistical Rigor Layer

Every workload ships more than point estimates — the layer a hardcore healthcare
AI team checks first. Computed in `scripts/m42_stats.py` (pure standard library,
deterministic, unit-tested, cross-validated against scipy):

- **Confidence intervals** — Wilson intervals for proportions (recall, coverage),
  **fast DeLong** analytic intervals for AUROC (the clinical-literature standard,
  O(N log N), validated to match the point estimate to machine precision), and
  percentile bootstrap for enrichment. No metric is reported without an interval.
- **Calibration** — Brier score and expected calibration error (ECE), with
  reliability bins. The classification workloads use calibrated synthetic scores
  (a latent risk drawn, the label sampled from it), so ECE is low by
  construction, the way a well-calibrated clinical model behaves.
- **Operating points** — sensitivity/specificity are reported at the
  clinically-chosen operating threshold (Youden's J, a sensitivity target for
  screening, or a precision target for trial matching), not a naive 0.5 cut.
- **Subgroup / fairness analysis** — every classifier reports AUROC per
  protected stratum (sex, age band, ancestry) with a disparity gap, plus
  per-class, per-tissue, per-target, and per-trial breakdowns.
- **Domain-specific rigor** — BEDROC early recognition (screening),
  Benjamini-Hochberg FDR control and genomic inflation λ (GWAS), differential-
  privacy budget accounting (RWE), membership-inference advantage and HIPAA Safe
  Harbor coverage (de-identification), data-poisoning detection (training
  provenance).

The rigor block is written into every workload's `sandbox-run-summary.json` and
`m42-value-scorecard.json`, and the gap audit (WL-007) fails if it is missing.

## Scale

Each workload is evaluated over a large, **balanced** synthetic cohort —
**100,000 cases across the platform, 10,000 per workload**. Med42 evaluation is a
full 10,000-case synthetic clinical-evaluation set (categories, specialties,
safety/escalation labels, benchmark outcomes, adversarial-prompt rejection); the
six hand-authored narrative vignettes remain in
`docs/workload-packs/m42/synthetic-vignettes.jsonl` for the qualitative
evidence-room walkthrough.

Metrics and confidence intervals are computed over the full cohort. The
operating-point selectors and AUROC variance are O(N log N) — the latter via
**fast DeLong**, the clinical-literature analytic interval — so scoring all ten
workloads at 100k stays a few seconds.

### Fixtures are generated, not committed

The synthetic fixtures (~35MB) are deterministic and regenerated by
`make m42-workloads-generate`; the generator in `scripts/m42_workloads.py` is the
committed source of truth, and the test suite proves byte-for-byte reproducibility.
Only the generator, packs, catalog, and evaluation protocols are tracked.

### Evidence sampling

Per-case cryptographic evidence is materialized for a **stratified review
sample** (up to 40 cases per workload spanning the confidence range) rather than
one file per case at this scale. The run summary records both the full
`cases_evaluated` count (10,000) and the `evidence_bundles_materialized` sample,
and the gap audit (EVID-001, WL-006) verifies they reconcile.

## Cryptographic Evidence — Real and Independently Verifiable

The Digital Seal is not a schema; it is real, dependency-free cryptography that
anyone can verify with the published public keys and zero trust in Aethelred
(`scripts/m42_crypto.py`, `scripts/m42_seal.py`):

- **Ed25519 (RFC 8032)** validator signature over the canonical seal body — a
  pure-Python implementation that passes the RFC 8032 and libsodium test vectors,
  so it interoperates with any Ed25519 library.
- **TEE remote attestation with a real two-link signature chain**: the enclave
  key signs a report whose `report_data` equals the digest of the model hash,
  circuit hash, and committed IO; a provisioning root signs the enclave key. The
  verifier checks the chain, a measurement allow-list, nonce freshness, and the
  report-data binding.
- **Schnorr NIZK (Fiat-Shamir, RFC 3526 group)** for zkML-tractable workloads —
  a real zero-knowledge proof bound to the committed IO. Large models (Med42) use
  the honest `tee_attested_commitments` mode, with zkML explicitly marked
  not-applicable and why; a full zk-SNARK of a clinical-LLM forward pass is not
  tractable today, and the code says so.
- **Pedersen-style hiding+binding commitments** to inputs and outputs, and a
  **Merkle batch anchor** with per-seal inclusion proofs (the value a chain
  settles).

### Post-quantum from the root (`scripts/m42_pqc.py`)

Every batch root carries a **hybrid Ed25519 + XMSS** signature. XMSS is a
stateful hash-based scheme (WOTS+ one-time keys over a Merkle tree, SHA3-256),
in the NIST FIPS 205 / SLH-DSA lineage — its security rests only on hash
preimage resistance, so a quantum computer running Grover's algorithm buys an
adversary at most a square-root speedup:

- **NIST security Category 5** (the highest tier): **256-bit classical, 128-bit
  post-quantum** strength.
- **A 2^128 work factor over a 128-bit baseline** (~3.4 × 10³⁸×). The brief
  asked for 20× better than a standard approach; the hash-based root exceeds that
  target by roughly a factor of 2^123 — not by tuning a parameter, but because
  hash-based security does not degrade under Shor's algorithm the way RSA/ECC
  signatures do.
- **Hybrid, so it binds two independent assumptions:** forging a batch root
  requires breaking *both* the elliptic-curve discrete log (classical strength
  today) *and* SHA3-256 preimage resistance (quantum strength). It is
  harvest-now-decrypt-later resistant: a seal anchored today stays unforgeable
  after a cryptographically relevant quantum computer exists.

`security_profile()` returns these numbers, the test suite asserts them
(`tests/m42/test_pqc.py`), and `make m42-bench` prints them.

### L1-grade speed: prove once, verify a block fast

Verifying a zero-knowledge proof for every seal individually is slow (~60–65
seals/sec — the NIZK modular exponentiation dominates), which is fine for a deep
audit but far too slow for block production. The seal uses the **rollup pattern**:
the expensive proof is verified **once at acceptance**, and a validator then
verifies a *block* of seals at signature-and-Merkle speed.

- **One hybrid signature and one TEE attestation per batch**, over the batch
  root — not per seal. Each seal proves membership by a Merkle inclusion proof.
- **Validator fast path: over 20,000 Digital Seals/sec** (≈21,600/sec at a 5,000-
  seal batch) — it checks the batch's hybrid signature, the attestation, and each
  seal's Merkle inclusion + digest binding, exactly as an L1 verifies a block
  header once and the transactions cheaply.
- **Full audit path** re-runs every NIZK and every attestation from scratch; the
  two paths are required to agree on validity in the test suite, so the fast path
  never accepts anything the deep audit would reject.

`make m42-bench` reports both paths and the primitive timings; the fixed-base
comb in the Ed25519 implementation is what keeps signing/verification in the
sub-millisecond-to-low-millisecond range without any native dependency.

**M42 verifies it themselves:** `make m42-verify` (or `scripts/m42-verify.py
--all --demo-tamper`) loads the published trust config
(`config/pilots/m42/trust-config.json`), verifies every seal end to end, and
demonstrates that **every forgery is rejected** — a swapped output, a forged
classical signature, a forged **post-quantum** signature leg, a substituted model
hash, a tampered attestation, an untrusted root, a weakened policy, a forged zk
proof, a tampered batch root, a replayed nonce. The negative controls run through
this same real verifier (not a mock), and the gap audit re-runs it
(CRYPTO-001/002/004). The only simulated element is the TEE *hardware* root — the
pilot uses a software test root, disclosed in CRYPTO-003; going live swaps in AMD
SEV-SNP / AWS Nitro roots with the seal format and verification logic unchanged.

## Test Suite

The platform is covered by **~23,700 automated tests** (`tests/m42/`, run with
`make m42-test`), enforced in CI, including a full cryptographic battery (RFC 8032
Ed25519 vectors, XMSS/WOTS+ post-quantum roundtrips and tamper rejection,
Merkle/Schnorr/attestation properties, and a seal tamper matrix where every
forgery — classical or post-quantum — must be rejected):

- Property-based invariants for every metric, parametrized across grids of
  hundreds of random seeds (AUROC bounds, label-flip symmetry, monotonic-transform
  invariance, PR-AUC, BEDROC, MCC range, confusion-matrix partition, threshold
  monotonicity, calibration bounds, subgroup disparity, and more).
- scipy cross-validation at scale: AUROC vs Mann-Whitney U and DeLong AUROC over
  wide seed/prevalence grids, BH-FDR vs `scipy.stats.false_discovery_control`,
  Wilson intervals over a dense (k, n) grid.
- Determinism of the RNG, of every workload's scoring, and byte-for-byte
  reproducibility of every generated fixture.
- Per-workload, per-metric and per-floor matrix tests over all ten workloads:
  balanced 10,000-case scale, result structure, every reported metric, every
  acceptance floor individually, proportion ranges, PHI scanning, and rigor-block
  presence.
- Adversarial evidence tests: removing or corrupting each required bundle field
  is rejected (every field x a representative workload spread), and all six
  negative controls reject across that spread.
- Catalog integrity, registry registration, pack completeness, and generator
  idempotence.

## Domain Metrics (computed, not asserted)

Every metric is computed from the embedded ground truth in each workload's
synthetic fixture, so an M42 reviewer can recompute every number. The drill is
deterministic, and each classification workload reports a confidence interval,
calibration, and subgroup fairness alongside the point estimate.

| Workload | Metrics measured | Acceptance floors |
|----------|------------------|-------------------|
| Genomic variant interpretation | concordance, pathogenic recall, benign specificity, clinically significant discordance, VUS rate | concordance >= 0.95, pathogenic recall >= 0.98, discordance = 0 |
| Med42 evaluation | clinical factuality, safety-flag recall, escalation match, benchmark accuracy, adverse-prompt rejection | factuality >= 0.95, safety recall >= 0.98, benchmark >= 0.85, adverse rejection = 1.0 |
| Retrospective radiology AI | AUROC, sensitivity, specificity, PPV, NPV, ECE, fairness AUROC gap, per-finding-type miss rate, critical-finding misses (reported) | AUROC >= 0.90, sensitivity >= 0.90, specificity >= 0.80, worst finding-type miss rate <= 0.12, ECE <= 0.10, fairness AUROC gap <= 0.20 |
| Drug-discovery screening | ROC-AUC, enrichment factor at 1% and 5%, top-100 hit rate | ROC-AUC >= 0.80, EF1% >= 10x, hit rate >= 0.10 |
| De-identification attestation | PHI recall, PHI precision, residual PHI in released set, k-anonymity, l-diversity, re-identification risk | PHI recall >= 0.98, residual PHI = 0, k-anonymity >= 5, l-diversity >= 2, re-id risk <= 0.2 |
| Population-health RWE | query determinism, count relative error, differential-privacy epsilon, small-cell suppression compliance | determinism >= 0.99, relative error <= 0.05, epsilon <= 1.0, suppression = 1.0 |
| Biobank GWAS / PRS | association power, false discovery rate, genomic inflation lambda, replication rate, PRS AUC | power >= 0.80, FDR <= 0.05, lambda <= 1.10, PRS AUC >= 0.65 |
| Digital pathology AI | slide AUROC, sensitivity, specificity, PPV, tile-localization AUROC, ECE, fairness AUROC gap, per-tissue miss rate, critical misses (reported) | slide AUROC >= 0.92, sensitivity >= 0.95, specificity >= 0.80, worst tissue miss rate <= 0.10, ECE <= 0.10, fairness AUROC gap <= 0.20 |
| Clinical-trial matching | matching sensitivity, specificity, precision, AUROC, false-match rate, synthetic-control SMD, fairness AUROC gap | matching sensitivity >= 0.75, matching AUROC >= 0.90, false-match rate <= 0.05, control-arm SMD <= 0.10, fairness AUROC gap <= 0.20 |
| Med42 training provenance | approved-data coverage, unapproved-data inclusion, lineage completeness, consent coverage, checkpoint-hash binding | approved coverage >= 0.99, unapproved inclusion = 0, lineage >= 0.95, consent >= 0.95 |

The clinically or commercially critical metric is foregrounded per workload:
pathogenic recall and zero clinically significant discordance for genomics;
sensitivity plus a **per-stratum blind-spot guard** — no individual critical-
finding type (radiology) or tissue (pathology) may be missed above a set rate,
which aggregate sensitivity alone can hide — for radiology and pathology;
enrichment factor for screening; **zero released residual PHI plus k-anonymity** for the
egress gate; **differential-privacy epsilon and small-cell suppression** for RWE;
**genomic inflation lambda** for population-stratification control in GWAS.

## Why the Tier 2 Workloads Are the Bigger Story

Tier 1 verifies M42's models. Tier 2 verifies M42's **data and the act of moving
it**, which is where the cross-border revenue and the regulatory risk both live:

- **De-identification attestation** is the unlock. No sovereign buyer or
  regulator accepts a dataset crossing a border on M42's word that PHI was
  removed. A Digital Seal proving PHI recall, zero released residual, and
  k-anonymity is the artifact that makes every other data sale possible.
- **Malaffi RWE** monetizes the flagship asset. The HIE's 3.5M+ records become
  saleable real-world evidence only when a pharma buyer or regulator can verify
  the cohort query ran on approved data, in-boundary, with a stated
  differential-privacy budget and small cells suppressed — without seeing a
  single record.
- **Biobank GWAS/PRS** turns 700K genomes into pharma-grade association evidence
  with proof the analysis never left the sovereign cohort.
- **Digital pathology** wraps a diagnostics service M42 already runs in
  verifiable evidence a referring system can audit.
- **Clinical-trial matching** gives IROS and pharma trial partners auditable
  eligibility decisions and a balanced synthetic control arm a regulator can
  accept in lieu of a randomized control.
- **Med42 training provenance** proves which approved, consented data trained a
  Med42 checkpoint — the prerequisite for licensing Med42 into other
  jurisdictions and for defending its IP.

## Architecture

| Component | File | Role |
|-----------|------|------|
| Workload engine | `scripts/m42_workloads.py` | Single source of truth: catalog, deterministic synthetic data, domain scorers, metric floors, model/circuit identity |
| Catalog | `config/pilots/m42/workloads/catalog.json` | Machine-readable list of all ten workloads and the active selection |
| Per-workload packs | `config/pilots/m42/workloads/<id>.json` | Policy, evidence contract, metric floors, and economics per workload |
| Synthetic fixtures | `docs/workload-packs/m42/workloads/<id>/synthetic.jsonl` | Domain-appropriate synthetic cases with embedded ground truth and model output; no PHI |
| Evaluation protocols | `docs/workload-packs/m42/workloads/<id>/evaluation-protocol.md` | Per-workload scope, metrics, floors, and boundary |
| Drill generator | `scripts/m42-sandbox-drill.py` | Produces hybrid evidence bundles, baseline/verified summaries, negative controls, value bank, and executive readout per workload |
| Registries | `config/pilots/m42/registry/{measurements,circuits}.json` | All ten workloads registered active with distinct model and circuit hashes |
| Gap audit | `scripts/m42-pilot-gap-audit.py` | WL-001..WL-006 validate the catalog, packs, registrations, fixtures, floors, and generated multi-workload evidence |

## Commands

```bash
# List the workloads
python3 scripts/m42-sandbox-drill.py --list

# Run one workload's drill (namespaced evidence for non-active workloads)
python3 scripts/m42-sandbox-drill.py --workload de-identification-attestation

# Run the active workload (canonical evidence path; same as make m42-sandbox-drill)
make m42-sandbox-drill

# Run all ten workloads + catalog scorecard
make m42-sandbox-drill-all

# Independently verify every Digital Seal and prove every forgery is rejected
make m42-verify

# Benchmark seal throughput (validator fast path vs full audit) + PQC profile
make m42-bench

# Regenerate packs and synthetic fixtures deterministically
make m42-workloads-generate

# Compute domain metrics for all workloads and enforce acceptance floors
make m42-workloads-score
```

## Evidence Contract (identical across workloads)

Every accepted case in every workload produces a hybrid evidence bundle binding
the workload's model hash and circuit hash: TEE attestation + zkML proof +
Digital Seal, with `require_both=true` and no single-evidence fallback. The
bundle schema is identical across workloads, so M42's reviewers learn one
evidence shape and apply it to all ten domains.

## Boundary

- Synthetic, non-live data only. No PHI, no live patient records, no M42
  production data in any workload. The de-identification workload operates on
  synthetic records with synthetic identifiers and proves the egress control,
  not on any real Malaffi data.
- The circuit binds inputs, outputs, policy, and TEE measurement. It does not
  prove scientific or clinical correctness; correctness is measured separately
  by the domain metrics against synthetic ground truth.
- Drill artifacts are pre-testnet fixtures. The live paid pilot replaces each
  workload's fixture digest with the M42-approved checkpoint or hosted endpoint
  digest and produces live hardware evidence before any production, clinical, or
  scientific claim.
