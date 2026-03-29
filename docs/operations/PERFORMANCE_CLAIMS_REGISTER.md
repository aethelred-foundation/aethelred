# Performance Claims Register

**Governed by:** `docs/operations/BENCHMARK_METHODOLOGY.md` (SQ16-BMS-001)
**Rule:** Every performance number in any external-facing material MUST appear in this register with status VERIFIED before publication. Unverified claims are flagged automatically and must not be used in decks, website copy, or investor materials.

---

## Status Definitions

| Status | Meaning |
|--------|---------|
| **VERIFIED** | Backed by a compliant benchmark report; peer-reviewed; reproduction confirmed |
| **UNVERIFIED** | Claimed but not yet backed by a compliant benchmark report |
| **RETRACTED** | Previously verified but invalidated (code change, hardware change, or age > 90 days) |
| **RE-VERIFICATION PENDING** | Previously verified; triggered for re-verification due to code or environment change |

---

## Automatic Invalidation Triggers

A VERIFIED claim transitions to RE-VERIFICATION PENDING if any of the following occur:
1. The benchmark commit hash is more than 90 days old
2. A breaking change is merged to the code path under measurement
3. The test hardware or topology changes from what was originally benchmarked

---

## Claims Register

| # | Claim | Source | Benchmark ID | Evidence Path | Reviewer | Verified Date | Expiry Date | Status |
|---|-------|--------|-------------|---------------|----------|--------------|-------------|--------|
| 1 | 2.8s deterministic finality (testnet, current) | Website io/index.html, org/index.html | — | — | — | — | — | **UNVERIFIED** |
| 2 | 12.5K TPS transfer throughput | Website io/index.html, org/index.html | — | — | — | — | — | **UNVERIFIED** |
| 3 | 650 jobs/s verified compute throughput | Website io/index.html, testnet.html | — | — | — | — | — | **UNVERIFIED** |
| 4 | 10,000+ verified jobs/s (internal planning target) | `DAY_ONE_10K_VERIFIED_JOBS_BLUEPRINT.md`, `DayOneTenKScalePlan()` in performance.go | MODEL-2026-001 | `test-results/truth-closeout/SQ01/` | — | — | — | **UNVERIFIED — INTERNAL PLANNING ONLY. Do not publish.** |
| 5 | 11,724.8 effective jobs/s across 3 lanes (fast 8192 + medium 2764.8 + heavy 768) | Same as #4 — model output, not measurement | MODEL-2026-001 | `test-results/truth-closeout/SQ15/` | — | — | — | **UNVERIFIED — INTERNAL PLANNING ONLY. Do not publish.** |

<!--
Add new claims above this line. Use the next sequential number.
Every claim MUST have:
- A specific, quantified claim (not vague language)
- The source where the claim appears (deck, website, whitepaper, blog)
- A benchmark ID linking to a compliant report
- An evidence path to the benchmark report file
- A reviewer who independently verified reproduction
- Verified and expiry dates (90-day window)
-->

---

## How to Register a New Claim

1. Add a row to the table above with status `UNVERIFIED`
2. Conduct a benchmark following `BENCHMARK_METHODOLOGY.md`
3. Save the report using the template at `docs/operations/templates/benchmark-report-template.md`
4. Have a second engineer reproduce the benchmark and sign off
5. Update the row with the benchmark ID, evidence path, reviewer, dates, and status `VERIFIED`
6. Set expiry date to verified date + 90 days

## Model-Derived vs. Hardware-Measured Claims

Claims #4 and #5 are **planning-model outputs**, not hardware measurements.

The `DayOneTenKScalePlan()` function in `x/pouw/keeper/performance.go` encodes the
architectural shape required for 10,000+ verified jobs/s. Its arithmetic is verified
by `TestDayOneTenKScalePlan_ValidAndExceedsTarget` in `performance_test.go`. The tests
confirm the model is internally consistent; they do not confirm that real hardware
achieves those numbers.

**Rule:** A model-derived number can only be promoted from `UNVERIFIED — INTERNAL PLANNING ONLY`
to `VERIFIED` after two independent benchmark runs on real hardware with the full three-lane
execution topology in place and reviewed by SQ15/SQ17 per the methodology in
`docs/operations/DAY_ONE_10K_VERIFIED_JOBS_BLUEPRINT.md`.

Any promotional copy, deck update, whitepaper change, or investor material that
cites `10,000+`, `11,724.8`, `8192`, `2764.8`, or `768` jobs/s MUST be blocked
by SQ04's CI gate until the claim row in this register carries status `VERIFIED`.

---

## How to Flag an Unverified Claim

If you encounter a performance number in any material that is not in this register:
1. Add it to the register with status `UNVERIFIED`
2. Note the source (deck name, slide number, URL, etc.)
3. Open an issue tagged `benchmark-verification` to track resolution
4. The claim MUST NOT be used in external materials until verified

## How to Retract a Claim

1. Change status to `RETRACTED`
2. Add a note in the Evidence Path column explaining the reason
3. Notify the marketing/content owner to remove the claim from materials
4. The retracted claim row is never deleted (audit trail)

---

## Quarterly Review

At each quarterly review:
1. All claims with expiry dates in the past are flagged as RE-VERIFICATION PENDING
2. All UNVERIFIED claims older than 30 days are escalated
3. All RETRACTED claims are reviewed to determine if re-benchmarking is warranted
4. The register is audited against all active external materials
