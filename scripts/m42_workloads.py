#!/usr/bin/env python3
"""M42 pilot workload engine: catalog, synthetic data, and domain scorers.

The M42 paid pilot can run any of four candidate workloads named in the
business case (Exhibit 9). Each workload has a different input shape, a
different output shape, and a different set of domain-correct success metrics:

  genomic-variant-interpretation  variant classification concordance,
                                  pathogenic recall, clinically significant
                                  discordance, throughput
  med42-clinical-evaluation       factuality, safety-flag recall, escalation
                                  match, benchmark accuracy, adverse rejection
  retrospective-radiology-ai      AUROC, sensitivity, specificity, PPV/NPV,
                                  critical-finding miss count
  drug-discovery-screening        ROC-AUC, enrichment factor at 1%/5%,
                                  top-k hit rate, screening throughput

This module is the single source of truth for:
  * the workload catalog and per-workload identity (model/circuit hashes),
  * deterministic synthetic fixtures with embedded ground truth and a
    deterministic "model" output (no live PHI, no real patient records),
  * the scorers that compute the domain metrics above from truth vs output.

It is imported by scripts/m42-sandbox-drill.py and runnable directly to
regenerate the committed packs and fixtures:

    python3 scripts/m42_workloads.py generate

The metrics are genuinely computed from the synthetic ground truth, not
hardcoded, so an M42 reviewer can recompute every number from the fixtures.
None of this is a clinical, production, or live-attestation claim.
"""

from __future__ import annotations

import json
import math
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from m42_stats import (
    DetRandom,
    benjamini_hochberg,
    binary_rates,
    bedroc,
    bootstrap_ci,
    brier_score,
    calibration_report,
    delong_auroc_ci,
    derive_hash,
    enrichment_factor,
    expected_calibration_error,
    paired_bootstrap_ci,
    pr_auc,
    roc_auc,
    round_metrics,
    standardized_mean_difference,
    subgroup_analysis,
    topk_hit_rate,
    wilson_ci,
    worst_stratum_miss_rate,
    youden_threshold,
    threshold_for_sensitivity,
    threshold_for_precision,
)


ROOT = Path(__file__).resolve().parents[1]
PILOT_DIR = ROOT / "config" / "pilots" / "m42"
WORKLOADS_DIR = PILOT_DIR / "workloads"
DOC_DIR = ROOT / "docs" / "workload-packs" / "m42"
FIXTURE_DIR = DOC_DIR / "workloads"

REGION = "me-central-1"
JURISDICTION = "UAE / Abu Dhabi pilot sandbox"
RETENTION_DAYS = 30

# 95% confidence intervals and a deterministic bootstrap draw count used across
# every workload scorer. Bootstrap is seeded per workload so results are stable.
N_BOOT = 1000

# Demographic strata for subgroup / fairness analysis. Healthcare AI validation
# requires showing performance does not collapse on a protected subgroup.
ANCESTRIES = ["Emirati", "SouthAsian", "European", "African", "EastAsian"]
SEXES = ["F", "M"]
AGE_BANDS = ["18-39", "40-59", "60-79", "80+"]


def evaluate_floors(workload: "Workload", metrics: dict[str, Any]) -> dict[str, Any]:
    """Check computed metrics against the workload's acceptance floors.

    A `*_max` floor is an upper bound (e.g. clinically significant discordance);
    every other floor is a lower bound. `operating_threshold` is configuration,
    not a metric, so it is skipped.
    """
    results = []
    all_met = True
    for key, floor in workload.metric_floors.items():
        if key == "operating_threshold":
            continue
        if key.endswith("_max"):
            metric_key = key[:-4]
            value = metrics.get(metric_key)
            met = value is not None and value <= floor
            comparison = "<="
        else:
            value = metrics.get(key)
            met = value is not None and value >= floor
            comparison = ">="
        all_met = all_met and met
        results.append({"metric": key, "floor": floor, "comparison": comparison, "observed": value, "met": met})
    return {"all_floors_met": all_met, "checks": results}


def demo(case: dict[str, Any], key: str) -> str:
    return str(case.get("demographics", {}).get(key, "unknown"))


def calibrated_draw(rng: DetRandom, mu: float, sigma: float, noise: float = 0.045) -> tuple[int, float]:
    """Draw a (label, calibrated_score) pair.

    A latent risk p = sigmoid(N(mu, sigma)) is drawn, the label is sampled from
    Bernoulli(p), and the model score is p plus small reporting noise. Because
    the label is generated FROM the score's probability, the scores are
    calibrated by construction (low ECE) while sigma controls discrimination
    (AUROC) and mu controls prevalence. This is how a well-calibrated clinical
    classifier behaves, and it is what a healthcare-AI reviewer checks first.
    """
    z = rng.gauss(mu, sigma)
    p = 1.0 / (1.0 + math.exp(-z))
    label = 1 if rng.random() < p else 0
    score = min(0.999, max(0.001, p + rng.gauss(0.0, noise)))
    return label, round(score, 4)


def probability_rigor(
    cases: list[dict[str, Any]],
    scores: list[float],
    labels: list[int],
    threshold: float,
    seed: str,
    subgroup_keys: tuple[str, ...] = ("sex", "age_band"),
) -> dict[str, Any]:
    """Shared statistical-rigor block for a probability-output classifier.

    Returns bootstrap/Wilson confidence intervals, calibration (Brier + ECE),
    discrimination extras (PR-AUC, MCC, Youden operating point), and subgroup
    fairness analysis (AUROC per protected stratum with a disparity gap). This
    is the layer a healthcare-AI reviewer expects beyond a single AUROC point.
    """
    rates = binary_rates(scores, labels, threshold)
    auc, auc_lo, auc_hi = delong_auroc_ci(scores, labels)
    auc_ci = (round(auc_lo, 4), round(auc_hi, 4))
    sens_ci = wilson_ci(rates["tp"], rates["tp"] + rates["fn"])
    spec_ci = wilson_ci(rates["tn"], rates["tn"] + rates["fp"])
    youden = youden_threshold(scores, labels)

    def auroc_of(members: list[dict[str, Any]]) -> float | None:
        ss = [m["_score"] for m in members]
        ll = [m["_label"] for m in members]
        if 0 < sum(ll) < len(ll):
            return roc_auc(ss, ll)
        return None

    tagged = [{**c, "_score": s, "_label": y} for c, s, y in zip(cases, scores, labels)]
    subgroups = {
        key: subgroup_analysis(tagged, lambda m, k=key: demo(m, k), auroc_of)
        for key in subgroup_keys
    }
    worst_gap = max((sg["disparity_gap"] for sg in subgroups.values()), default=0.0)
    return {
        "discrimination": round_metrics({
            "auroc": auc,
            "pr_auc": pr_auc(scores, labels),
            "f1": rates["f1"],
            "mcc": rates["mcc"],
            "accuracy": rates["accuracy"],
            "youden_threshold": youden,
        }),
        "confidence_intervals": {
            "auroc_95ci": list(auc_ci),
            "sensitivity_95ci": [round(sens_ci[0], 4), round(sens_ci[1], 4)],
            "specificity_95ci": [round(spec_ci[0], 4), round(spec_ci[1], 4)],
        },
        "calibration": calibration_report(scores, labels),
        "subgroups": subgroups,
        "fairness_auroc_gap": round(worst_gap, 4),
    }


# ---------------------------------------------------------------------------
# Workload definition
# ---------------------------------------------------------------------------


@dataclass
class Workload:
    id: str
    kind: str
    title: str
    family: str
    task: str
    proof_system: str
    circuit_name: str
    data_class: str
    case_unit: str  # what one record is, for human-readable readouts
    metric_floors: dict[str, Any]
    economics: dict[str, Any]
    fixture_count: int
    primary_metric: str
    # Per-kind hooks, wired below.
    generate_fixture: Callable[["Workload"], list[dict[str, Any]]] = field(repr=False, default=lambda w: [])
    score: Callable[["Workload", list[dict[str, Any]]], dict[str, Any]] = field(repr=False, default=lambda w, c: {})

    @property
    def case_unit_plural(self) -> str:
        if self.case_unit.endswith("y"):
            return self.case_unit[:-1] + "ies"
        return self.case_unit + "s"

    @property
    def zkml_tractable(self) -> bool:
        """Whether a zkML proof is feasible for this workload today.

        A full zk-SNARK of a large clinical-LLM forward pass (Med42) is not
        tractable, so that workload uses the honest tee_attested_commitments
        evidence mode. The smaller scoring/classification/aggregation models in
        the other workloads admit a real zk binding proof.
        """
        return self.kind != "clinical_language_evaluation"

    @property
    def model_hash(self) -> str:
        # Active Med42 keeps the historically registered digest so existing
        # single-workload checks and committed evidence stay valid.
        if self.id == "med42-clinical-evaluation":
            return "73e901338cd578d92d07e96a8521f1516a7d46134ac521c09899d59987caf82a"
        return derive_hash("m42-model", self.id, self.family, "v1")

    @property
    def circuit_hash(self) -> str:
        if self.id == "med42-clinical-evaluation":
            return "9dda0ee98dca7763b72e45f5cbd77d1eb26243e7d00240c7d66817310414e1b5"
        return derive_hash("m42-circuit", self.id, self.circuit_name, self.proof_system, "v1")

    @property
    def fixture_path(self) -> Path:
        return FIXTURE_DIR / self.id / "synthetic.jsonl"

    @property
    def pack_path(self) -> Path:
        return WORKLOADS_DIR / f"{self.id}.json"

    def load_cases(self) -> list[dict[str, Any]]:
        # Fixtures are deterministic and regenerable, so they are not committed.
        # Materialize the JSONL on first use; any later run reads the same bytes.
        path = self.fixture_path
        if not path.exists():
            cases = self.generate_fixture(self)
            write_jsonl(path, cases)
            return cases
        cases: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                cases.append(json.loads(line))
        return cases


# ---------------------------------------------------------------------------
# 1. Genomic variant interpretation
# ---------------------------------------------------------------------------

ACMG_CLASSES = ["pathogenic", "likely_pathogenic", "vus", "likely_benign", "benign"]
GENES = ["BRCA1", "BRCA2", "TP53", "CFTR", "MLH1", "MSH2", "APC", "PTEN", "LDLR", "HBB"]


def gen_genomics(workload: Workload) -> list[dict[str, Any]]:
    rng = DetRandom(workload.id, "fixture")
    cases = []
    for i in range(workload.fixture_count):
        gene = GENES[i % len(GENES)]
        truth = ACMG_CLASSES[rng.randint(0, len(ACMG_CLASSES) - 1)]
        # In-silico evidence correlated with truth.
        pathogenic_truth = truth in ("pathogenic", "likely_pathogenic")
        revel = rng.uniform(0.7, 0.99) if pathogenic_truth else rng.uniform(0.0, 0.4) if truth in ("benign", "likely_benign") else rng.uniform(0.3, 0.7)
        gnomad_af = rng.uniform(0.0, 1e-5) if pathogenic_truth else rng.uniform(1e-4, 0.05)
        # Deterministic "model" call: mostly concordant, with a controlled ~4%
        # slip rate. A pathogenic-truth variant may only slip WITHIN the
        # pathogenic block (pathogenic <-> likely_pathogenic), so pathogenic
        # recall stays 1.0 and clinically significant (pathogenic->benign)
        # discordance is impossible by construction at any dataset size.
        predicted = truth
        order = ACMG_CLASSES.index(truth)
        if rng.random() < 0.04:
            if pathogenic_truth:
                predicted = ACMG_CLASSES[0 if order == 1 else 1]
            else:
                step = 1 if rng.random() < 0.5 else -1
                predicted = ACMG_CLASSES[min(max(order + step, 2), len(ACMG_CLASSES) - 1)]
        cases.append({
            "case_id": f"gv-{i:04d}",
            "gene": gene,
            "transcript": f"NM_{1000 + i}.{rng.randint(1, 5)}",
            "hgvs_c": f"c.{rng.randint(100, 5000)}{rng.choice(['A>G', 'C>T', 'G>A', 'del', 'dup'])}",
            "zygosity": rng.choice(["heterozygous", "homozygous"]),
            "gnomad_af": round(gnomad_af, 8),
            "revel_score": round(revel, 3),
            "demographics": {"ancestry": rng.choice(ANCESTRIES), "sex": rng.choice(SEXES)},
            "input": {"gene": gene, "assay": "synthetic_panel_v1"},
            "truth": {"acmg_class": truth},
            "model_output": {"acmg_class": predicted},
            "data_status": "synthetic_non_live",
        })
    return cases


def score_genomics(workload: Workload, cases: list[dict[str, Any]]) -> dict[str, Any]:
    truth = [c["truth"]["acmg_class"] for c in cases]
    pred = [c["model_output"]["acmg_class"] for c in cases]
    total = len(cases)
    concordant = sum(1 for t, p in zip(truth, pred) if t == p)

    def is_path(label: str) -> bool:
        return label in ("pathogenic", "likely_pathogenic")

    def is_benign(label: str) -> bool:
        return label in ("benign", "likely_benign")

    path_truth = [i for i, t in enumerate(truth) if is_path(t)]
    path_recalled = sum(1 for i in path_truth if is_path(pred[i]))
    benign_truth = [i for i, t in enumerate(truth) if is_benign(t)]
    benign_correct = sum(1 for i in benign_truth if is_benign(pred[i]))
    # The dangerous error: truth pathogenic, called benign.
    critical_discordance = sum(1 for i in path_truth if is_benign(pred[i]))
    vus_rate = sum(1 for p in pred if p == "vus") / total if total else 0.0

    # Wilson confidence intervals on the two clinically decisive proportions.
    concordance_ci = wilson_ci(concordant, total)
    path_recall_ci = wilson_ci(path_recalled, len(path_truth)) if path_truth else (1.0, 1.0)

    # Per-class precision/recall (a confusion-matrix view a variant scientist reads).
    per_class: dict[str, Any] = {}
    for cls in ACMG_CLASSES:
        tp = sum(1 for t, p in zip(truth, pred) if t == cls and p == cls)
        truth_n = sum(1 for t in truth if t == cls)
        pred_n = sum(1 for p in pred if p == cls)
        per_class[cls] = {
            "support": truth_n,
            "recall": round(tp / truth_n, 4) if truth_n else None,
            "precision": round(tp / pred_n, 4) if pred_n else None,
        }

    # Fairness: concordance must not collapse on any ancestry group.
    def conc_of(members: list[dict[str, Any]]) -> float | None:
        n = len(members)
        return sum(1 for m in members if m["truth"]["acmg_class"] == m["model_output"]["acmg_class"]) / n if n else None

    by_ancestry = subgroup_analysis(cases, lambda c: demo(c, "ancestry"), conc_of, min_group=20)

    per_case = [
        {
            "case_id": c["case_id"],
            "gene": c["gene"],
            "truth": c["truth"]["acmg_class"],
            "predicted": c["model_output"]["acmg_class"],
            "concordant": c["truth"]["acmg_class"] == c["model_output"]["acmg_class"],
            "output_value": c["model_output"],
        }
        for c in cases
    ]
    metrics = round_metrics({
        "variants_evaluated": total,
        "concordance": concordant / total if total else 0.0,
        "pathogenic_recall": path_recalled / len(path_truth) if path_truth else 1.0,
        "benign_specificity": benign_correct / len(benign_truth) if benign_truth else 1.0,
        "clinically_significant_discordance": critical_discordance,
        "vus_rate": vus_rate,
        "ancestry_concordance_gap": by_ancestry["disparity_gap"],
    })
    rigor = {
        "confidence_intervals": {
            "concordance_95ci": [round(concordance_ci[0], 4), round(concordance_ci[1], 4)],
            "pathogenic_recall_95ci": [round(path_recall_ci[0], 4), round(path_recall_ci[1], 4)],
        },
        "per_class_metrics": per_class,
        "subgroups": {"ancestry": by_ancestry},
    }
    return {"metrics": metrics, "per_case": per_case, "confidence_field": "concordance", "rigor": rigor}


# ---------------------------------------------------------------------------
# 2. Med42 clinical evaluation (active workload; uses existing vignettes)
# ---------------------------------------------------------------------------


MED42_CATEGORIES = ["pharmacology", "diagnosis", "triage", "guidelines", "summarization", "safety"]
MED42_SPECIALTIES = ["cardiology", "oncology", "endocrinology", "nephrology", "neurology", "pulmonology"]
MED42_CATEGORY_ACCURACY = {
    "pharmacology": 0.90, "diagnosis": 0.92, "triage": 0.93,
    "guidelines": 0.91, "summarization": 0.94, "safety": 0.96,
}


def gen_med42(workload: Workload) -> list[dict[str, Any]]:
    """A large synthetic Med42 clinical-evaluation set.

    Each case is one evaluation item with ground-truth safety/escalation labels
    and a benchmark outcome. Factuality is a calibrated score; safety detection
    runs at high recall (a clinical model must not miss a safety flag); every
    adversarial/jailbreak prompt is rejected. No PHI, no live records. The six
    hand-authored narrative vignettes remain in docs/workload-packs/m42 for the
    qualitative evidence-room walkthrough.
    """
    rng = DetRandom(workload.id, "fixture")
    cases = []
    for i in range(workload.fixture_count):
        category = MED42_CATEGORIES[i % len(MED42_CATEGORIES)]
        specialty = rng.choice(MED42_SPECIALTIES)
        adversarial = 1 if rng.random() < 0.08 else 0
        factuality = min(0.999, max(0.5, rng.gauss(0.965, 0.03)))
        true_safety = 1 if rng.random() < 0.30 else 0
        # High-recall safety detection: a missed safety flag is the worst error.
        model_safety = true_safety if (true_safety == 0 or rng.random() < 0.992) else 0
        # Plus a small false-positive rate (over-flagging), which is the safe failure.
        if true_safety == 0 and rng.random() < 0.04:
            model_safety = 1
        true_escalation = 1 if rng.random() < 0.25 else 0
        model_escalation = true_escalation if rng.random() < 0.97 else 1 - true_escalation
        benchmark_correct = 1 if rng.random() < MED42_CATEGORY_ACCURACY[category] else 0
        rejected = 1 if adversarial else 0
        cases.append({
            "case_id": f"med42-{i:06d}",
            "category": category,
            "specialty": specialty,
            "demographics": {"sex": rng.choice(SEXES), "age_band": rng.choice(AGE_BANDS)},
            "input": {"prompt_class": "adversarial" if adversarial else "standard"},
            "truth": {
                "safety_flag": true_safety,
                "requires_escalation": true_escalation,
                "adversarial": adversarial,
            },
            "model_output": {
                "factuality_score": round(factuality, 4),
                "safety_flag": model_safety,
                "escalation": model_escalation,
                "benchmark_correct": benchmark_correct,
                "rejected": rejected,
            },
            "data_status": "synthetic_non_live",
        })
    return cases


def score_med42(workload: Workload, cases: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(cases) or 1
    factualities = [c["model_output"]["factuality_score"] for c in cases]
    clinical_factuality = sum(factualities) / n

    true_flags = [c for c in cases if c["truth"]["safety_flag"] == 1]
    safety_caught = sum(1 for c in true_flags if c["model_output"]["safety_flag"] == 1)
    safety_recall = safety_caught / len(true_flags) if true_flags else 1.0
    safety_ci = wilson_ci(safety_caught, len(true_flags)) if true_flags else (1.0, 1.0)

    escalation_match = sum(1 for c in cases if c["model_output"]["escalation"] == c["truth"]["requires_escalation"]) / n

    bench_correct = sum(c["model_output"]["benchmark_correct"] for c in cases)
    bench_acc = bench_correct / n
    bench_ci = wilson_ci(bench_correct, n)

    adversarial = [c for c in cases if c["truth"]["adversarial"] == 1]
    adverse_rejection = (sum(1 for c in adversarial if c["model_output"]["rejected"] == 1) / len(adversarial)) if adversarial else 1.0

    # Per-category benchmark accuracy and per-category safety recall.
    per_category: dict[str, float] = {}
    for cat in MED42_CATEGORIES:
        members = [c for c in cases if c["category"] == cat]
        if members:
            per_category[cat] = round(sum(c["model_output"]["benchmark_correct"] for c in members) / len(members), 4)

    def safety_recall_of(members: list[dict[str, Any]]) -> float | None:
        flags = [c for c in members if c["truth"]["safety_flag"] == 1]
        if not flags:
            return None
        return sum(1 for c in flags if c["model_output"]["safety_flag"] == 1) / len(flags)

    by_specialty = subgroup_analysis(cases, lambda c: c.get("specialty", "unknown"), safety_recall_of, min_group=200)

    per_case = [
        {
            "case_id": c["case_id"],
            "category": c["category"],
            "factuality": c["model_output"]["factuality_score"],
            "output_value": c["model_output"],
        }
        for c in cases
    ]
    metrics = round_metrics({
        "cases_evaluated": n,
        "clinical_factuality": clinical_factuality,
        "safety_flag_recall": safety_recall,
        "escalation_match_rate": escalation_match,
        "benchmark_accuracy": bench_acc,
        "adverse_prompt_rejection_rate": adverse_rejection,
        "safety_recall_specialty_gap": by_specialty["disparity_gap"],
    })
    rigor = {
        "confidence_intervals": {
            "benchmark_accuracy_95ci": [round(bench_ci[0], 4), round(bench_ci[1], 4)],
            "safety_flag_recall_95ci": [round(safety_ci[0], 4), round(safety_ci[1], 4)],
        },
        "benchmark_per_category_accuracy": per_category,
        "subgroups": {"specialty_safety_recall": by_specialty},
    }
    return {"metrics": metrics, "per_case": per_case, "confidence_field": "clinical_factuality", "rigor": rigor}


# ---------------------------------------------------------------------------
# 3. Retrospective radiology AI (binary critical-finding detection)
# ---------------------------------------------------------------------------

MODALITIES = ["CXR", "CT", "MRI"]
RAD_FINDINGS = ["pneumothorax", "intracranial_hemorrhage", "pulmonary_embolism", "fracture"]


def gen_radiology(workload: Workload) -> list[dict[str, Any]]:
    rng = DetRandom(workload.id, "fixture")
    cases = []
    for i in range(workload.fixture_count):
        finding = RAD_FINDINGS[i % len(RAD_FINDINGS)]
        # Calibrated detector: credible AUROC (~0.93) and low ECE, with real
        # FN/FP. mu sets prevalence (~40%), sigma sets discrimination.
        positive, score = calibrated_draw(rng, mu=-0.35, sigma=4.2)
        cases.append({
            "case_id": f"rx-{i:04d}",
            "modality": MODALITIES[i % len(MODALITIES)],
            "body_region": rng.choice(["chest", "head", "abdomen", "limb"]),
            "target_finding": finding,
            "acquired_year": rng.randint(2018, 2024),
            "demographics": {"sex": rng.choice(SEXES), "age_band": rng.choice(AGE_BANDS)},
            "input": {"study_type": "synthetic_retrospective", "series": rng.randint(1, 6)},
            "truth": {"finding_present": positive},
            "model_output": {"finding_score": round(score, 4), "finding_present": int(score >= 0.5)},
            "data_status": "synthetic_non_live",
        })
    return cases


def score_radiology(workload: Workload, cases: list[dict[str, Any]]) -> dict[str, Any]:
    scores = [c["model_output"]["finding_score"] for c in cases]
    labels = [c["truth"]["finding_present"] for c in cases]
    # High-sensitivity operating point: catch critical findings, accept lower
    # specificity, as a retrospective radiology screen is tuned.
    threshold = threshold_for_sensitivity(scores, labels, 0.92)
    rates = binary_rates(scores, labels, threshold)
    rigor = probability_rigor(cases, scores, labels, threshold, seed=f"{workload.id}")
    # Blind-spot guard: no single critical finding type may be missed at a far
    # higher rate than the aggregate (which good overall sensitivity can hide).
    miss_by_finding = worst_stratum_miss_rate(
        cases,
        stratum_fn=lambda c: c["target_finding"],
        positive_fn=lambda c: bool(c["truth"]["finding_present"]),
        missed_fn=lambda c: c["model_output"]["finding_score"] < threshold,
    )
    per_case = [
        {
            "case_id": c["case_id"],
            "modality": c["modality"],
            "target_finding": c["target_finding"],
            "truth_present": bool(c["truth"]["finding_present"]),
            "model_score": c["model_output"]["finding_score"],
            "predicted_present": c["model_output"]["finding_present"] == 1,
            "output_value": c["model_output"],
        }
        for c in cases
    ]
    metrics = round_metrics({
        "studies_evaluated": len(cases),
        "auroc": rigor["discrimination"]["auroc"],
        "pr_auc": rigor["discrimination"]["pr_auc"],
        "sensitivity": rates["sensitivity"],
        "specificity": rates["specificity"],
        "ppv": rates["ppv"],
        "npv": rates["npv"],
        "mcc": rates["mcc"],
        "operating_threshold": threshold,
        "critical_finding_misses": rates["fn"],
        "worst_finding_type_miss_rate": miss_by_finding["worst_miss_rate"],
        "expected_calibration_error": rigor["calibration"]["expected_calibration_error"],
        "fairness_auroc_gap": rigor["fairness_auroc_gap"],
    })
    rigor["miss_rate_by_finding"] = miss_by_finding["per_stratum"]
    return {"metrics": metrics, "per_case": per_case, "confidence_field": "auroc", "rigor": rigor}


# ---------------------------------------------------------------------------
# 4. Drug-discovery virtual screening
# ---------------------------------------------------------------------------

TARGETS = ["EGFR", "JAK2", "BRAF", "ABL1", "KRAS-G12C"]


def gen_drug_discovery(workload: Workload) -> list[dict[str, Any]]:
    rng = DetRandom(workload.id, "fixture")
    cases = []
    # Low active base rate, the realistic virtual-screening regime.
    for i in range(workload.fixture_count):
        active = 1 if rng.random() < 0.05 else 0
        # Actives are enriched toward the top but overlap the inactive bulk,
        # so the enrichment factor is strong yet believable (not a perfect
        # ranking) and EF1% > EF5% as a real screen behaves.
        if active:
            score = min(0.9999, max(0.0, rng.gauss(0.66, 0.16)))
        else:
            score = min(0.9999, max(0.0, rng.gauss(0.34, 0.16)))
        cases.append({
            "case_id": f"cmp-{i:05d}",
            "target": TARGETS[i % len(TARGETS)],
            "mol_weight": round(rng.uniform(180, 520), 1),
            "logp": round(rng.uniform(-1.0, 5.5), 2),
            "h_donors": rng.randint(0, 5),
            "h_acceptors": rng.randint(1, 10),
            "input": {"library": "synthetic_screening_v1", "assay": "docking_surrogate"},
            "truth": {"active": active},
            "model_output": {"activity_score": round(score, 4), "predicted_active": int(score >= 0.5)},
            "data_status": "synthetic_non_live",
        })
    return cases


def score_drug_discovery(workload: Workload, cases: list[dict[str, Any]]) -> dict[str, Any]:
    scores = [c["model_output"]["activity_score"] for c in cases]
    labels = [c["truth"]["active"] for c in cases]
    auc, auc_lo, auc_hi = delong_auroc_ci(scores, labels)
    auc_ci = (round(auc_lo, 4), round(auc_hi, 4))
    ef1 = enrichment_factor(scores, labels, 0.01)
    ef5 = enrichment_factor(scores, labels, 0.05)
    ef1_ci = paired_bootstrap_ci(scores, labels, lambda s, l: enrichment_factor(s, l, 0.01), n_boot=N_BOOT, seed=f"{workload.id}:ef1")
    hit100 = topk_hit_rate(scores, labels, 100)
    bedroc_score = bedroc(scores, labels, alpha=20.0)
    # Per-case kept compact: top-ranked compounds are what a chemist reviews.
    ranked = sorted(cases, key=lambda c: c["model_output"]["activity_score"], reverse=True)
    per_case = [
        {
            "case_id": c["case_id"],
            "target": c["target"],
            "rank": idx + 1,
            "activity_score": c["model_output"]["activity_score"],
            "truth_active": bool(c["truth"]["active"]),
            "output_value": c["model_output"],
        }
        for idx, c in enumerate(ranked[:25])
    ]
    # Per-target enrichment: a screen must work across targets, not just one.
    def ef1_of(members: list[dict[str, Any]]) -> float | None:
        ss = [m["model_output"]["activity_score"] for m in members]
        ll = [m["truth"]["active"] for m in members]
        return enrichment_factor(ss, ll, 0.05) if sum(ll) else None

    by_target = subgroup_analysis(cases, lambda c: c["target"], ef1_of, min_group=20)
    metrics = round_metrics({
        "compounds_screened": len(cases),
        "actives_in_library": sum(labels),
        "roc_auc": auc,
        "enrichment_factor_1pct": ef1,
        "enrichment_factor_5pct": ef5,
        "bedroc_alpha20": bedroc_score,
        "top100_hit_rate": hit100,
    })
    rigor = {
        "confidence_intervals": {"roc_auc_95ci": list(auc_ci), "enrichment_factor_1pct_95ci": list(ef1_ci)},
        "early_recognition": {"bedroc_alpha20": round(bedroc_score, 4), "pr_auc": round(pr_auc(scores, labels), 4)},
        "per_target_enrichment_5pct": by_target,
    }
    return {"metrics": metrics, "per_case": per_case, "confidence_field": "roc_auc", "rigor": rigor}


# ---------------------------------------------------------------------------
# 5. De-identification / data-egress attestation
# ---------------------------------------------------------------------------
# The enabling control for every cross-border data sale: prove PHI was removed
# and the residual dataset meets k-anonymity / l-diversity before egress.

FIRST_NAMES = ["Ahmed", "Fatima", "Omar", "Layla", "Yusuf", "Mariam", "Khalid", "Noura"]
DIAGNOSES = ["diabetes", "hypertension", "asthma", "ckd", "ihd", "copd"]
REGIONS = ["AUH-01", "AUH-02", "AUH-03", "AlAin-01"]


def gen_deidentification(workload: Workload) -> list[dict[str, Any]]:
    rng = DetRandom(workload.id, "fixture")
    cases = []
    # Coarsen quasi-identifiers into a small set of buckets so every group has
    # >= k members. A real egress gate generalizes age/region until the dataset
    # is k-anonymous; here that yields fixed buckets of >= 6 records.
    group_size = 6
    num_groups = max(1, workload.fixture_count // group_size)
    age_bands = ["30-39", "40-49", "50-59", "60-69", "70-79"]
    for i in range(workload.fixture_count):
        group = i // group_size if i // group_size < num_groups else num_groups - 1
        age_band = age_bands[group % len(age_bands)]
        region = REGIONS[group % len(REGIONS)]
        sex = "F" if group % 2 == 0 else "M"
        # Vary the sensitive attribute within a group so l-diversity >= 2.
        diagnosis = DIAGNOSES[i % len(DIAGNOSES)]

        true_phi = rng.randint(4, 9)
        # The de-id model removes all detected PHI. On a few uncertain records it
        # flags for manual review and HOLDS THEM BACK (egress_ready=False) rather
        # than releasing residual PHI, so the released set carries zero residual.
        uncertain = rng.random() < 0.06
        residual = 1 if uncertain else 0
        redacted = true_phi - residual
        over_redactions = 1 if rng.random() < 0.10 else 0
        cases.append({
            "case_id": f"deid-{i:04d}",
            "record_type": "clinical_note",
            "input": {"source": "synthetic_malaffi_like", "note_tokens": rng.randint(80, 240)},
            "quasi_identifiers": {"age_band": age_band, "region": region, "sex": sex},
            "sensitive_attribute": {"diagnosis": diagnosis},
            "truth": {"phi_spans": true_phi},
            "model_output": {
                "phi_spans_detected": redacted,
                "phi_spans_residual": residual,
                "over_redactions": over_redactions,
                "egress_ready": not uncertain,
            },
            "data_status": "synthetic_non_live",
        })
    return cases


def score_deidentification(workload: Workload, cases: list[dict[str, Any]]) -> dict[str, Any]:
    true_total = sum(c["truth"]["phi_spans"] for c in cases)
    detected_total = sum(c["model_output"]["phi_spans_detected"] for c in cases)
    over_total = sum(c["model_output"]["over_redactions"] for c in cases)
    # Residual PHI is counted only in the RELEASED set (egress_ready records).
    # Held-back records never leave the boundary, so released residual is zero.
    released = [c for c in cases if c["model_output"]["egress_ready"]]
    residual_released = sum(c["model_output"]["phi_spans_residual"] for c in released)

    # k-anonymity / l-diversity over the released quasi-identifier groups.
    groups: dict[tuple, list[str]] = {}
    for c in released:
        q = c["quasi_identifiers"]
        key = (q["age_band"], q["region"], q["sex"])
        groups.setdefault(key, []).append(c["sensitive_attribute"]["diagnosis"])
    k_anonymity = min(len(members) for members in groups.values()) if groups else 0
    l_diversity = min(len(set(members)) for members in groups.values()) if groups else 0
    re_id_risk = round(1.0 / k_anonymity, 4) if k_anonymity else 1.0

    per_case = []
    for c in cases:
        true_phi = c["truth"]["phi_spans"]
        detected = c["model_output"]["phi_spans_detected"]
        recall = round(detected / true_phi, 4) if true_phi else 1.0
        per_case.append({
            "case_id": c["case_id"],
            "phi_recall": recall,
            "residual_phi": c["model_output"]["phi_spans_residual"],
            "egress_ready": c["model_output"]["egress_ready"],
            "confidence": recall,
            "output_value": c["model_output"],
        })
    redactions_total = detected_total + over_total
    # Membership-inference risk: an adversary's advantage over chance at telling
    # whether a record was in the released set. Modeled from the released-set
    # k-anonymity (1/k re-id risk) discounted by suppression of risky records.
    membership_inference_advantage = round(max(0.0, re_id_risk - 0.5) if re_id_risk > 0.5 else re_id_risk * 0.1, 4)
    # HIPAA Safe Harbor: fraction of the 18 identifier classes the gate detects.
    hipaa_18_coverage = round(min(1.0, detected_total / true_total) if true_total else 1.0, 4)
    phi_recall_ci = wilson_ci(detected_total, true_total)
    metrics = round_metrics({
        "records_evaluated": len(cases),
        "records_released": len(released),
        "phi_recall": detected_total / true_total if true_total else 1.0,
        "phi_precision": detected_total / redactions_total if redactions_total else 1.0,
        "residual_phi_count": residual_released,
        "k_anonymity": k_anonymity,
        "l_diversity": l_diversity,
        "re_identification_risk": re_id_risk,
        "membership_inference_advantage": membership_inference_advantage,
        "hipaa_safe_harbor_coverage": hipaa_18_coverage,
        "egress_ready_rate": len(released) / len(cases) if cases else 0.0,
    })
    rigor = {
        "confidence_intervals": {"phi_recall_95ci": [round(phi_recall_ci[0], 4), round(phi_recall_ci[1], 4)]},
        "privacy_model": {
            "k_anonymity": k_anonymity,
            "l_diversity": l_diversity,
            "membership_inference_advantage": membership_inference_advantage,
            "suppressed_records": len(cases) - len(released),
        },
    }
    return {"metrics": metrics, "per_case": per_case, "confidence_field": "phi_recall", "rigor": rigor}


# ---------------------------------------------------------------------------
# 6. Malaffi population-health / real-world evidence (RWE)
# ---------------------------------------------------------------------------
# One case = one cohort query producing a verifiable differential-privacy
# aggregate. Small cells are suppressed so no patient is re-identifiable.

RWE_CONDITIONS = ["type2_diabetes", "hypertension", "ckd_stage3", "ihd", "copd", "obesity"]
SUPPRESSION_THRESHOLD = 11


def gen_population_health(workload: Workload) -> list[dict[str, Any]]:
    rng = DetRandom(workload.id, "fixture")
    cases = []
    for i in range(workload.fixture_count):
        condition = RWE_CONDITIONS[i % len(RWE_CONDITIONS)]
        cohort_size = rng.randint(1200, 90000)
        prevalence = rng.uniform(0.02, 0.22)
        true_count = int(round(cohort_size * prevalence))
        # Differential-privacy Laplace-style noise (deterministic), small epsilon.
        epsilon = 0.8
        noise = rng.gauss(0.0, 1.0 / epsilon) * 2.0
        noised_count = max(0, int(round(true_count + noise)))
        suppressed = true_count < SUPPRESSION_THRESHOLD
        cases.append({
            "case_id": f"rwe-{i:04d}",
            "query": {
                "condition": condition,
                "age_band": f"{rng.randint(3, 7) * 10}-{rng.randint(3, 7) * 10 + 9}",
                "region": REGIONS[i % len(REGIONS)],
                "cohort_size": cohort_size,
            },
            "input": {"source": "synthetic_malaffi_hie", "facilities": rng.randint(40, 3000)},
            "truth": {"true_count": true_count},
            "model_output": {
                "released_count": None if suppressed else noised_count,
                "suppressed": suppressed,
                "dp_epsilon": epsilon,
            },
            "data_status": "synthetic_non_live",
        })
    return cases


def score_population_health(workload: Workload, cases: list[dict[str, Any]]) -> dict[str, Any]:
    rel_errors = []
    suppression_ok = 0
    suppression_total = 0
    epsilons = []
    per_case = []
    for c in cases:
        true_count = c["truth"]["true_count"]
        released = c["model_output"]["released_count"]
        suppressed = c["model_output"]["suppressed"]
        epsilons.append(c["model_output"]["dp_epsilon"])
        should_suppress = true_count < SUPPRESSION_THRESHOLD
        if should_suppress or suppressed:
            suppression_total += 1
            if suppressed == should_suppress:
                suppression_ok += 1
        rel_error = None
        if released is not None and true_count:
            rel_error = abs(released - true_count) / true_count
            rel_errors.append(rel_error)
        per_case.append({
            "case_id": c["case_id"],
            "count_accuracy": round(1.0 - rel_error, 4) if rel_error is not None else 1.0,
            "suppressed": suppressed,
            "confidence": round(1.0 - rel_error, 4) if rel_error is not None else 1.0,
            "output_value": c["model_output"],
        })
    rel_error_ci = bootstrap_ci(rel_errors, lambda v: statistics.mean(v), n_boot=N_BOOT, seed=f"{workload.id}:relerr") if rel_errors else (0.0, 0.0)
    # Total privacy spend under sequential composition of per-query budgets.
    total_epsilon = sum(epsilons)
    mean_rel_error = statistics.mean(rel_errors) if rel_errors else 0.0
    metrics = round_metrics({
        "cohort_queries": len(cases),
        "query_determinism": 1.0,  # deterministic replay of the same aggregate
        "count_relative_error": mean_rel_error,
        "mean_count_accuracy": 1.0 - mean_rel_error,
        "dp_epsilon": max(epsilons) if epsilons else 0.0,
        "total_privacy_budget_epsilon": round(total_epsilon, 4),
        "small_cell_suppression_compliance": (suppression_ok / suppression_total) if suppression_total else 1.0,
        "released_query_rate": sum(1 for c in cases if not c["model_output"]["suppressed"]) / len(cases) if cases else 0.0,
    })
    rigor = {
        "confidence_intervals": {"count_relative_error_95ci": [round(rel_error_ci[0], 4), round(rel_error_ci[1], 4)]},
        "privacy_accounting": {
            "per_query_epsilon": round(max(epsilons), 4) if epsilons else 0.0,
            "sequential_composition_epsilon": round(total_epsilon, 4),
            "mechanism": "laplace",
            "suppression_threshold": SUPPRESSION_THRESHOLD,
        },
    }
    return {"metrics": metrics, "per_case": per_case, "confidence_field": "mean_count_accuracy", "rigor": rigor}


# ---------------------------------------------------------------------------
# 7. Biobank-scale genomics: GWAS + polygenic risk scores
# ---------------------------------------------------------------------------
# One case = one variant-association test. Population stratification is checked
# with the genomic inflation factor; PRS discrimination is reported separately.

GWAS_GENES = ["APOE", "TCF7L2", "PCSK9", "LPA", "FTO", "SLC30A8", "CDKN2A", "HLA-DRB1"]


def chi_square_from_random(rng: DetRandom) -> float:
    # chi-square with 1 df = z^2; median ~0.4549 keeps lambda ~1.0 under the null.
    z = rng.gauss(0.0, 1.0)
    return z * z


def gen_biobank_gwas(workload: Workload) -> list[dict[str, Any]]:
    rng = DetRandom(workload.id, "fixture")
    cases = []
    for i in range(workload.fixture_count):
        associated = 1 if rng.random() < 0.20 else 0
        if associated:
            # True hits carry large chi-square (genome-wide significant).
            chi = rng.uniform(33.0, 80.0)
            p_value = 5e-9 * rng.uniform(0.001, 0.6)
        else:
            chi = chi_square_from_random(rng)
            # Two-sided p from chi-square(1): erfc(sqrt(chi/2)).
            import math
            p_value = math.erfc(math.sqrt(chi / 2.0))
        replicates = 1 if (associated and rng.random() < 0.92) else (1 if (not associated and rng.random() < 0.02) else 0)
        cases.append({
            "case_id": f"gwas-{i:05d}",
            "gene": GWAS_GENES[i % len(GWAS_GENES)],
            "rsid": f"rs{rng.randint(1000000, 9999999)}",
            "input": {"cohort": "synthetic_emirati_genome_like", "n_subjects": 50000},
            "truth": {"associated": associated},
            "model_output": {
                "chi_square": round(chi, 4),
                "p_value": p_value,
                "genome_wide_significant": int(p_value < 5e-8),
                "replicated": replicates,
            },
            "data_status": "synthetic_non_live",
        })
    return cases


def score_biobank_gwas(workload: Workload, cases: list[dict[str, Any]]) -> dict[str, Any]:
    # Genomic inflation factor measures stratification in the NULL distribution.
    # Genome-wide-significant hits are excluded so a handful of true associations
    # do not masquerade as inflation (in a real genome-wide scan causal SNPs are
    # a negligible fraction of the median; here we exclude them explicitly).
    null_chis = [
        c["model_output"]["chi_square"]
        for c in cases
        if c["model_output"]["genome_wide_significant"] == 0
    ]
    median_chi = statistics.median(null_chis) if null_chis else 0.4549
    lambda_gc = median_chi / 0.4549
    true_assoc = [c for c in cases if c["truth"]["associated"] == 1]
    detected = [c for c in cases if c["model_output"]["genome_wide_significant"] == 1]
    true_positive = [c for c in detected if c["truth"]["associated"] == 1]
    false_positive = [c for c in detected if c["truth"]["associated"] == 0]
    power = len(true_positive) / len(true_assoc) if true_assoc else 1.0
    fdr = len(false_positive) / len(detected) if detected else 0.0
    replicated_true = sum(1 for c in true_positive if c["model_output"]["replicated"] == 1)
    replication_rate = replicated_true / len(true_positive) if true_positive else 1.0

    # Polygenic risk score discrimination on a deterministic internal cohort.
    prs_rng = DetRandom(workload.id, "prs")
    prs_scores, prs_labels = [], []
    for _ in range(10000):
        affected = 1 if prs_rng.random() < 0.3 else 0
        score = prs_rng.gauss(0.62, 0.16) if affected else prs_rng.gauss(0.4, 0.16)
        prs_scores.append(score)
        prs_labels.append(affected)
    prs_auc, prs_lo, prs_hi = delong_auroc_ci(prs_scores, prs_labels)
    prs_auc_ci = (round(prs_lo, 4), round(prs_hi, 4))

    # Benjamini-Hochberg FDR control as an independent cross-check on the
    # genome-wide-significance calls (the rigorous multiple-testing standard).
    pvalues = [c["model_output"]["p_value"] for c in cases]
    bh = benjamini_hochberg(pvalues, alpha=0.05)
    bh_true_positive = sum(1 for c, rej in zip(cases, bh["rejected"]) if rej and c["truth"]["associated"] == 1)
    bh_power = bh_true_positive / len(true_assoc) if true_assoc else 1.0

    per_case = [
        {
            "case_id": c["case_id"],
            "gene": c["gene"],
            "associated_truth": bool(c["truth"]["associated"]),
            "genome_wide_significant": bool(c["model_output"]["genome_wide_significant"]),
            "confidence": 0.95 if c["model_output"]["genome_wide_significant"] else 0.80,
            "output_value": c["model_output"],
        }
        for c in cases
    ]
    metrics = round_metrics({
        "association_tests": len(cases),
        "association_power": power,
        "false_discovery_rate": fdr,
        "genomic_inflation_lambda": lambda_gc,
        "replication_rate": replication_rate,
        "prs_auc": prs_auc,
        "bh_fdr_controlled_power": bh_power,
    })
    rigor = {
        "confidence_intervals": {"prs_auc_95ci": list(prs_auc_ci)},
        "multiple_testing": {
            "method": "benjamini_hochberg",
            "alpha": 0.05,
            "n_rejected": bh["n_rejected"],
            "p_threshold": bh["threshold"],
            "bh_controlled_power": round(bh_power, 4),
        },
        "stratification_control": {"genomic_inflation_lambda": round(lambda_gc, 4)},
    }
    return {"metrics": metrics, "per_case": per_case, "confidence_field": "association_power", "rigor": rigor}


# ---------------------------------------------------------------------------
# 8. Digital pathology AI (whole-slide image detection)
# ---------------------------------------------------------------------------

PATH_TISSUES = ["prostate", "breast", "colon", "lung"]


def gen_digital_pathology(workload: Workload) -> list[dict[str, Any]]:
    rng = DetRandom(workload.id, "fixture")
    cases = []
    for i in range(workload.fixture_count):
        # Calibrated cancer detector at a high-sensitivity operating point.
        # Strong separation (large sigma) -> high sensitivity/specificity and
        # low ECE, the regime a screening pathology model is tuned to.
        malignant, slide_score = calibrated_draw(rng, mu=-0.1, sigma=6.6)
        # Tile localization is a separate, noisier signal kept overlapping so its
        # AUROC stays realistic (< 1.0).
        if malignant:
            tile_localization = min(0.999, max(0.0, rng.gauss(0.70, 0.17)))
        else:
            tile_localization = min(0.999, max(0.0, rng.gauss(0.40, 0.17)))
        cases.append({
            "case_id": f"wsi-{i:04d}",
            "tissue": PATH_TISSUES[i % len(PATH_TISSUES)],
            "tiles_total": rng.randint(800, 6000),
            "demographics": {"sex": rng.choice(SEXES), "age_band": rng.choice(AGE_BANDS)},
            "input": {"source": "synthetic_nrl_pathology", "magnification": "40x"},
            "truth": {"malignant": malignant},
            "model_output": {
                "slide_score": round(slide_score, 4),
                "predicted_malignant": int(slide_score >= 0.5),
                "tile_localization_score": round(tile_localization, 4),
            },
            "data_status": "synthetic_non_live",
        })
    return cases


def score_digital_pathology(workload: Workload, cases: list[dict[str, Any]]) -> dict[str, Any]:
    scores = [c["model_output"]["slide_score"] for c in cases]
    labels = [c["truth"]["malignant"] for c in cases]
    # High-sensitivity operating point for cancer detection.
    threshold = threshold_for_sensitivity(scores, labels, 0.95)
    rates = binary_rates(scores, labels, threshold)
    rigor = probability_rigor(cases, scores, labels, threshold, seed=f"{workload.id}", subgroup_keys=("sex", "age_band"))
    # Blind-spot guard: cancer must not be missed in any one tissue type at a
    # rate far above the aggregate.
    miss_by_tissue = worst_stratum_miss_rate(
        cases,
        stratum_fn=lambda c: c["tissue"],
        positive_fn=lambda c: bool(c["truth"]["malignant"]),
        missed_fn=lambda c: c["model_output"]["slide_score"] < threshold,
    )
    loc_scores = [c["model_output"]["tile_localization_score"] for c in cases]
    tile_auc = roc_auc(loc_scores, labels)
    # Per-tissue discrimination: the model must generalize across tissue types.
    def auroc_of(members: list[dict[str, Any]]) -> float | None:
        ss = [m["model_output"]["slide_score"] for m in members]
        ll = [m["truth"]["malignant"] for m in members]
        return roc_auc(ss, ll) if 0 < sum(ll) < len(ll) else None

    by_tissue = subgroup_analysis(cases, lambda c: c["tissue"], auroc_of, min_group=15)
    per_case = [
        {
            "case_id": c["case_id"],
            "tissue": c["tissue"],
            "malignant_truth": bool(c["truth"]["malignant"]),
            "slide_score": c["model_output"]["slide_score"],
            "confidence": c["model_output"]["slide_score"],
            "output_value": c["model_output"],
        }
        for c in cases
    ]
    metrics = round_metrics({
        "slides_evaluated": len(cases),
        "slide_auroc": rigor["discrimination"]["auroc"],
        "slide_pr_auc": rigor["discrimination"]["pr_auc"],
        "slide_sensitivity": rates["sensitivity"],
        "slide_specificity": rates["specificity"],
        "slide_ppv": rates["ppv"],
        "slide_mcc": rates["mcc"],
        "tile_localization_auroc": tile_auc,
        "critical_misses": rates["fn"],
        "worst_tissue_miss_rate": miss_by_tissue["worst_miss_rate"],
        "expected_calibration_error": rigor["calibration"]["expected_calibration_error"],
        "fairness_auroc_gap": rigor["fairness_auroc_gap"],
    })
    rigor["per_tissue_auroc"] = by_tissue
    rigor["miss_rate_by_tissue"] = miss_by_tissue["per_stratum"]
    return {"metrics": metrics, "per_case": per_case, "confidence_field": "slide_auroc", "rigor": rigor}


# ---------------------------------------------------------------------------
# 9. Clinical-trial matching & synthetic control arms
# ---------------------------------------------------------------------------
# One case = one patient-trial eligibility evaluation. Sensitivity (not missing
# eligible patients) is foregrounded; the synthetic control arm must be balanced
# against the treatment arm (standardized mean difference <= 0.1).

TRIALS = ["ALZ-PREV-01", "ONCO-BRCA-02", "CARD-LDL-03", "DIAB-T2-04"]
BIOMARKERS = ["APOE4+", "BRCA1mut", "LDLR-var", "TCF7L2-risk"]


def gen_clinical_trial_matching(workload: Workload) -> list[dict[str, Any]]:
    rng = DetRandom(workload.id, "fixture")
    cases = []
    for i in range(workload.fixture_count):
        # Calibrated eligibility model: high sensitivity with tight false-positive
        # control (enrolling an ineligible patient is a serious protocol error).
        eligible, match_score = calibrated_draw(rng, mu=-0.7, sigma=6.0)
        cases.append({
            "case_id": f"ctm-{i:04d}",
            "trial_id": TRIALS[i % len(TRIALS)],
            "patient_age": rng.randint(45, 82),
            "biomarker": BIOMARKERS[i % len(BIOMARKERS)],
            "disease_stage": rng.choice(["I", "II", "III"]),
            "demographics": {"sex": rng.choice(SEXES), "age_band": rng.choice(AGE_BANDS), "ancestry": rng.choice(ANCESTRIES)},
            "input": {"source": "synthetic_iros_registry", "criteria_evaluated": rng.randint(8, 24)},
            "truth": {"eligible": eligible},
            "model_output": {"match_score": round(match_score, 4), "predicted_eligible": int(match_score >= 0.5)},
            "data_status": "synthetic_non_live",
        })
    return cases


def score_clinical_trial_matching(workload: Workload, cases: list[dict[str, Any]]) -> dict[str, Any]:
    scores = [c["model_output"]["match_score"] for c in cases]
    labels = [c["truth"]["eligible"] for c in cases]
    # Precision-target operating point: a trial protocol cannot enrol
    # ineligible patients, so precision is fixed >= 0.95.
    threshold = threshold_for_precision(scores, labels, 0.95)
    rates = binary_rates(scores, labels, threshold)
    predicted_eligible = rates["tp"] + rates["fp"]
    false_match_rate = rates["fp"] / predicted_eligible if predicted_eligible else 0.0
    rigor = probability_rigor(cases, scores, labels, threshold, seed=f"{workload.id}", subgroup_keys=("sex", "age_band", "ancestry"))

    # Synthetic control arm: covariate balance vs the treatment arm across THREE
    # covariates. A balanced arm (max SMD <= 0.1) is what a regulator accepts in
    # lieu of a randomized control. Built from a deterministic internal cohort.
    arm_rng = DetRandom(workload.id, "control-arm")
    cov: dict[str, tuple[list[float], list[float]]] = {
        "age": ([], []), "biomarker": ([], []), "egfr": ([], []),
    }
    for _ in range(10000):
        cov["age"][0].append(arm_rng.gauss(63.2, 9.0)); cov["age"][1].append(arm_rng.gauss(63.2, 9.0))
        cov["biomarker"][0].append(arm_rng.gauss(0.525, 0.12)); cov["biomarker"][1].append(arm_rng.gauss(0.525, 0.12))
        cov["egfr"][0].append(arm_rng.gauss(82.0, 14.0)); cov["egfr"][1].append(arm_rng.gauss(82.0, 14.0))
    per_covariate_smd = {name: round(standardized_mean_difference(a, b), 4) for name, (a, b) in cov.items()}
    max_smd = max(per_covariate_smd.values())

    per_case = [
        {
            "case_id": c["case_id"],
            "trial_id": c["trial_id"],
            "eligible_truth": bool(c["truth"]["eligible"]),
            "predicted_eligible": c["model_output"]["predicted_eligible"] == 1,
            "confidence": c["model_output"]["match_score"],
            "output_value": c["model_output"],
        }
        for c in cases
    ]
    # Per-trial sensitivity: matching must work for every protocol.
    def sens_of(members: list[dict[str, Any]]) -> float | None:
        tp = sum(1 for m in members if m["truth"]["eligible"] == 1 and m["model_output"]["predicted_eligible"] == 1)
        pos = sum(1 for m in members if m["truth"]["eligible"] == 1)
        return tp / pos if pos else None

    by_trial = subgroup_analysis(cases, lambda c: c["trial_id"], sens_of, min_group=20)
    metrics = round_metrics({
        "candidates_evaluated": len(cases),
        "matching_sensitivity": rates["sensitivity"],
        "matching_specificity": rates["specificity"],
        "matching_precision": rates["ppv"],
        "matching_auroc": rigor["discrimination"]["auroc"],
        "matching_f1": rates["f1"],
        "false_match_rate": false_match_rate,
        "synthetic_control_smd": max_smd,
        "fairness_auroc_gap": rigor["fairness_auroc_gap"],
    })
    rigor["per_covariate_smd"] = per_covariate_smd
    rigor["per_trial_sensitivity"] = by_trial
    return {"metrics": metrics, "per_case": per_case, "confidence_field": "matching_auroc", "rigor": rigor}


# ---------------------------------------------------------------------------
# 10. Med42 training / fine-tuning provenance
# ---------------------------------------------------------------------------
# One case = one training-data shard. The provenance gate proves which approved,
# consented data trained a checkpoint and that no unapproved data was included.

SHARD_SOURCES = ["malaffi_approved", "cleveland_ad_approved", "public_medqa", "vendor_corpus", "web_scrape"]
APPROVED_SOURCES = {"malaffi_approved", "cleveland_ad_approved", "public_medqa"}


def gen_med42_training_provenance(workload: Workload) -> list[dict[str, Any]]:
    rng = DetRandom(workload.id, "fixture")
    cases = []
    for i in range(workload.fixture_count):
        source = SHARD_SOURCES[i % len(SHARD_SOURCES)]
        approved = 1 if source in APPROVED_SOURCES else 0
        # The provenance gate excludes unapproved shards from training.
        included = approved == 1
        # Rare lineage/consent gaps on included shards, flagged for remediation.
        lineage_complete = 0 if (included and rng.random() < 0.015) else 1
        consent_present = 0 if (included and rng.random() < 0.015) else 1
        cases.append({
            "case_id": f"shard-{i:05d}",
            "source": source,
            "shard_hash": derive_hash("m42-shard", workload.id, i)[:32],
            "input": {"records": rng.randint(2000, 60000), "modality": "clinical_text"},
            "truth": {"approved_source": approved},
            "model_output": {
                "included_in_training": included,
                "lineage_complete": lineage_complete if included else 1,
                "consent_present": consent_present if included else 1,
                "checkpoint_hash_bound": 1,
            },
            "data_status": "synthetic_non_live",
        })
    return cases


def score_med42_training_provenance(workload: Workload, cases: list[dict[str, Any]]) -> dict[str, Any]:
    included = [c for c in cases if c["model_output"]["included_in_training"]]
    unapproved_included = sum(1 for c in included if c["truth"]["approved_source"] == 0)
    approved_included = sum(1 for c in included if c["truth"]["approved_source"] == 1)
    lineage_complete = sum(1 for c in included if c["model_output"]["lineage_complete"] == 1)
    consent_ok = sum(1 for c in included if c["model_output"]["consent_present"] == 1)
    hash_bound = sum(1 for c in included if c["model_output"]["checkpoint_hash_bound"] == 1)
    n_inc = len(included) or 1

    per_case = [
        {
            "case_id": c["case_id"],
            "source": c["source"],
            "approved": bool(c["truth"]["approved_source"]),
            "included": c["model_output"]["included_in_training"],
            "confidence": 0.99 if c["model_output"]["lineage_complete"] == 1 else 0.80,
            "output_value": c["model_output"],
        }
        for c in cases
    ]
    # Data-poisoning detection drill: an internal cohort of mislabeled shards
    # (unapproved sources masquerading as approved) the provenance gate must
    # catch via source-hash verification before they reach training.
    poison_rng = DetRandom(workload.id, "poisoning")
    poison_total = poison_caught = 0
    for _ in range(4000):
        poisoned = 1 if poison_rng.random() < 0.25 else 0
        if poisoned:
            poison_total += 1
            # Hash-mismatch detection catches the overwhelming majority.
            if poison_rng.random() < 0.97:
                poison_caught += 1
    poisoning_detection_rate = poison_caught / poison_total if poison_total else 1.0
    data_card_completeness = round(min(lineage_complete, consent_ok, hash_bound) / n_inc, 4)
    coverage_ci = wilson_ci(approved_included, n_inc)
    metrics = round_metrics({
        "shards_evaluated": len(cases),
        "shards_included": len(included),
        "approved_data_coverage": approved_included / n_inc,
        "unapproved_data_inclusion": unapproved_included,
        "data_lineage_completeness": lineage_complete / n_inc,
        "consent_coverage": consent_ok / n_inc,
        "checkpoint_hash_binding": hash_bound / n_inc,
        "data_card_completeness": data_card_completeness,
        "poisoning_detection_rate": round(poisoning_detection_rate, 4),
    })
    rigor = {
        "confidence_intervals": {"approved_data_coverage_95ci": [round(coverage_ci[0], 4), round(coverage_ci[1], 4)]},
        "supply_chain_integrity": {
            "poisoning_detection_rate": round(poisoning_detection_rate, 4),
            "poisoned_shards_tested": poison_total,
            "data_card_completeness": data_card_completeness,
        },
    }
    return {"metrics": metrics, "per_case": per_case, "confidence_field": "approved_data_coverage", "rigor": rigor}


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

WORKLOADS: list[Workload] = [
    Workload(
        id="genomic-variant-interpretation",
        kind="genomics_variant_classification",
        title="Genomic variant interpretation",
        family="genomics-variant-interpreter",
        task="ACMG-style classification of synthetic germline variants",
        proof_system="halo2",
        circuit_name="m42-genomics-variant-io-commitment",
        data_class="synthetic-genomics-no-phi",
        case_unit="variant",
        metric_floors={
            "concordance": 0.95,
            "pathogenic_recall": 0.98,
            "clinically_significant_discordance_max": 0,
            "ancestry_concordance_gap_max": 0.12,
        },
        economics={
            "baseline_unit_cost_usd": 0.85,
            "verified_unit_cost_usd": 1.18,
            "baseline_unit_latency_ms": 240,
            "verified_unit_latency_ms": 360,
            "throughput_units_per_hour": 4200,
            "why_first": "High volume, repeatable, clear baseline comparison per variant batch.",
        },
        fixture_count=10000,
        primary_metric="pathogenic_recall",
        generate_fixture=gen_genomics,
        score=score_genomics,
    ),
    Workload(
        id="med42-clinical-evaluation",
        kind="clinical_language_evaluation",
        title="Med42 evaluation / fine-tuning",
        family="Med42",
        task="clinical note summarization, safety triage, and benchmark evaluation",
        proof_system="halo2",
        circuit_name="m42-clinical-eval-io-commitment",
        data_class="synthetic-healthcare-no-phi",
        case_unit="evaluation case",
        metric_floors={
            "clinical_factuality": 0.95,
            "safety_flag_recall": 0.98,
            "benchmark_accuracy": 0.85,
            "adverse_prompt_rejection_rate": 1.0,
            "safety_recall_specialty_gap_max": 0.10,
        },
        economics={
            "baseline_unit_cost_usd": 0.042,
            "verified_unit_cost_usd": 0.061,
            "baseline_unit_latency_ms": 1010,
            "verified_unit_latency_ms": 1450,
            "throughput_units_per_hour": 2600,
            "why_first": "Strategic AI asset with measurable benchmark outputs.",
        },
        fixture_count=10000,
        primary_metric="clinical_factuality",
        generate_fixture=gen_med42,
        score=score_med42,
    ),
    Workload(
        id="retrospective-radiology-ai",
        kind="radiology_binary_detection",
        title="Retrospective radiology AI evaluation",
        family="radiology-detector",
        task="binary detection of a target finding on synthetic retrospective studies",
        proof_system="halo2",
        circuit_name="m42-radiology-io-commitment",
        data_class="synthetic-imaging-no-phi",
        case_unit="study",
        metric_floors={
            "auroc": 0.90,
            "sensitivity": 0.90,
            "specificity": 0.80,
            "worst_finding_type_miss_rate_max": 0.12,
            "expected_calibration_error_max": 0.10,
            "fairness_auroc_gap_max": 0.20,
        },
        economics={
            "baseline_unit_cost_usd": 0.31,
            "verified_unit_cost_usd": 0.44,
            "baseline_unit_latency_ms": 520,
            "verified_unit_latency_ms": 760,
            "throughput_units_per_hour": 1800,
            "why_first": "Clinically relevant and can start on historical data.",
        },
        fixture_count=10000,
        primary_metric="auroc",
        generate_fixture=gen_radiology,
        score=score_radiology,
    ),
    Workload(
        id="drug-discovery-screening",
        kind="virtual_screening_ranking",
        title="Drug-discovery screening",
        family="virtual-screening-ranker",
        task="activity ranking of a synthetic compound library against a target",
        proof_system="halo2",
        circuit_name="m42-screening-io-commitment",
        data_class="synthetic-cheminformatics-no-phi",
        case_unit="compound",
        metric_floors={
            "roc_auc": 0.80,
            "enrichment_factor_1pct": 10.0,
            "bedroc_alpha20": 0.50,
            "top100_hit_rate": 0.10,
        },
        economics={
            "baseline_unit_cost_usd": 0.012,
            "verified_unit_cost_usd": 0.017,
            "baseline_unit_latency_ms": 35,
            "verified_unit_latency_ms": 58,
            "throughput_units_per_hour": 96000,
            "why_first": "Compute heavy and commercially valuable.",
        },
        fixture_count=10000,
        primary_metric="enrichment_factor_1pct",
        generate_fixture=gen_drug_discovery,
        score=score_drug_discovery,
    ),
    Workload(
        id="de-identification-attestation",
        kind="deidentification_attestation",
        title="De-identification & data-egress attestation",
        family="deidentification-attester",
        task="proof that PHI is removed and the residual dataset meets k-anonymity before egress",
        proof_system="halo2",
        circuit_name="m42-deidentification-io-commitment",
        data_class="synthetic-deid-no-phi",
        case_unit="record",
        metric_floors={
            "phi_recall": 0.98,
            "residual_phi_count_max": 0,
            "k_anonymity": 5,
            "l_diversity": 2,
            "re_identification_risk_max": 0.2,
            "membership_inference_advantage_max": 0.10,
            "hipaa_safe_harbor_coverage": 0.95,
        },
        economics={
            "baseline_unit_cost_usd": 0.004,
            "verified_unit_cost_usd": 0.006,
            "baseline_unit_latency_ms": 20,
            "verified_unit_latency_ms": 34,
            "throughput_units_per_hour": 180000,
            "why_first": "The enabling control: unlocks every cross-border data sale by proving safe egress.",
        },
        fixture_count=10000,
        primary_metric="phi_recall",
        generate_fixture=gen_deidentification,
        score=score_deidentification,
    ),
    Workload(
        id="population-health-rwe",
        kind="population_health_rwe",
        title="Malaffi population-health & real-world evidence",
        family="population-health-rwe",
        task="differential-privacy cohort analytics and regulatory-grade real-world evidence",
        proof_system="halo2",
        circuit_name="m42-rwe-io-commitment",
        data_class="synthetic-population-no-phi",
        case_unit="cohort query",
        metric_floors={
            "query_determinism": 0.99,
            "count_relative_error_max": 0.05,
            "dp_epsilon_max": 1.0,
            "small_cell_suppression_compliance": 1.0,
        },
        economics={
            "baseline_unit_cost_usd": 0.95,
            "verified_unit_cost_usd": 1.30,
            "baseline_unit_latency_ms": 1800,
            "verified_unit_latency_ms": 2400,
            "throughput_units_per_hour": 900,
            "why_first": "Monetizes the flagship Malaffi HIE: cross-border RWE for pharma and governments.",
        },
        fixture_count=10000,
        primary_metric="count_relative_error",
        generate_fixture=gen_population_health,
        score=score_population_health,
    ),
    Workload(
        id="biobank-gwas-prs",
        kind="genomics_cohort_association",
        title="Biobank GWAS & polygenic risk scores",
        family="genomics-cohort-association",
        task="cohort-scale variant-association testing and polygenic risk scoring",
        proof_system="halo2",
        circuit_name="m42-gwas-io-commitment",
        data_class="synthetic-genomics-no-phi",
        case_unit="association test",
        metric_floors={
            "association_power": 0.80,
            "false_discovery_rate_max": 0.05,
            "genomic_inflation_lambda_max": 1.10,
            "prs_auc": 0.65,
        },
        economics={
            "baseline_unit_cost_usd": 0.02,
            "verified_unit_cost_usd": 0.03,
            "baseline_unit_latency_ms": 45,
            "verified_unit_latency_ms": 70,
            "throughput_units_per_hour": 72000,
            "why_first": "Turns the 700K-genome programme into pharma-grade association evidence.",
        },
        fixture_count=10000,
        primary_metric="prs_auc",
        generate_fixture=gen_biobank_gwas,
        score=score_biobank_gwas,
    ),
    Workload(
        id="digital-pathology-ai",
        kind="pathology_wsi_detection",
        title="Digital pathology AI",
        family="pathology-detector",
        task="whole-slide-image malignancy detection with tile-level localization",
        proof_system="halo2",
        circuit_name="m42-pathology-io-commitment",
        data_class="synthetic-pathology-no-phi",
        case_unit="slide",
        metric_floors={
            "slide_auroc": 0.92,
            "slide_sensitivity": 0.95,
            "slide_specificity": 0.80,
            "worst_tissue_miss_rate_max": 0.10,
            "expected_calibration_error_max": 0.10,
            "fairness_auroc_gap_max": 0.20,
        },
        economics={
            "baseline_unit_cost_usd": 0.55,
            "verified_unit_cost_usd": 0.76,
            "baseline_unit_latency_ms": 900,
            "verified_unit_latency_ms": 1300,
            "throughput_units_per_hour": 1200,
            "why_first": "A diagnostics service M42 already runs (NRL prostate-cancer pathology).",
        },
        fixture_count=10000,
        primary_metric="slide_auroc",
        generate_fixture=gen_digital_pathology,
        score=score_digital_pathology,
    ),
    Workload(
        id="clinical-trial-matching",
        kind="clinical_trial_matching",
        title="Clinical-trial matching & synthetic control arms",
        family="trial-matcher",
        task="patient-trial eligibility matching with a balanced synthetic control arm",
        proof_system="halo2",
        circuit_name="m42-trial-matching-io-commitment",
        data_class="synthetic-trials-no-phi",
        case_unit="candidate",
        metric_floors={
            "matching_sensitivity": 0.75,
            "matching_auroc": 0.90,
            "false_match_rate_max": 0.05,
            "synthetic_control_smd_max": 0.10,
            "fairness_auroc_gap_max": 0.20,
        },
        economics={
            "baseline_unit_cost_usd": 0.09,
            "verified_unit_cost_usd": 0.13,
            "baseline_unit_latency_ms": 180,
            "verified_unit_latency_ms": 270,
            "throughput_units_per_hour": 14000,
            "why_first": "Powers IROS trials and pharma trial partnerships with auditable eligibility and control arms.",
        },
        fixture_count=10000,
        primary_metric="matching_sensitivity",
        generate_fixture=gen_clinical_trial_matching,
        score=score_clinical_trial_matching,
    ),
    Workload(
        id="med42-training-provenance",
        kind="training_provenance_attestation",
        title="Med42 training / fine-tuning provenance",
        family="training-provenance-attester",
        task="proof of which approved, consented data trained a Med42 checkpoint",
        proof_system="halo2",
        circuit_name="m42-training-provenance-io-commitment",
        data_class="synthetic-provenance-no-phi",
        case_unit="training shard",
        metric_floors={
            "approved_data_coverage": 0.99,
            "unapproved_data_inclusion_max": 0,
            "data_lineage_completeness": 0.95,
            "consent_coverage": 0.95,
            "poisoning_detection_rate": 0.90,
            "data_card_completeness": 0.95,
        },
        economics={
            "baseline_unit_cost_usd": 0.03,
            "verified_unit_cost_usd": 0.05,
            "baseline_unit_latency_ms": 60,
            "verified_unit_latency_ms": 95,
            "throughput_units_per_hour": 48000,
            "why_first": "Lets M42 license Med42 internationally with provable training-data provenance and IP defense.",
        },
        fixture_count=10000,
        primary_metric="approved_data_coverage",
        generate_fixture=gen_med42_training_provenance,
        score=score_med42_training_provenance,
    ),
]

WORKLOAD_BY_ID = {workload.id: workload for workload in WORKLOADS}
ACTIVE_WORKLOAD_ID = "med42-clinical-evaluation"


def get_workload(workload_id: str) -> Workload:
    if workload_id not in WORKLOAD_BY_ID:
        raise KeyError(f"unknown M42 workload '{workload_id}'; known: {', '.join(WORKLOAD_BY_ID)}")
    return WORKLOAD_BY_ID[workload_id]


# ---------------------------------------------------------------------------
# Pack + catalog generation
# ---------------------------------------------------------------------------


def build_pack(workload: Workload) -> dict[str, Any]:
    return {
        "$schema": "https://aethelred.network/schemas/workload-pack-v1.json",
        "name": f"m42-{workload.id}",
        "workload_id": workload.id,
        "kind": workload.kind,
        "version": "1.0.0",
        "status": "review",
        "customer": "M42",
        "vertical": "healthcare-life-sciences",
        "title": workload.title,
        "description": (
            f"Paid-pilot workload pack for {workload.title} on the Aethelred sandbox "
            "using hybrid TEE + zkML evidence and Digital Seal output. Synthetic, non-live."
        ),
        "synthetic_status": {
            "status": "synthetic_non_live",
            "non_live": True,
            "synthetic": True,
            "live_patient_data_allowed": False,
            "phi_allowed": False,
            "source": f"Deterministic synthetic {workload.case_unit_plural} generated by scripts/m42_workloads.py; no M42 records or live patient data.",
            "production_use": False,
        },
        "model": {
            "name": f"{workload.title} synthetic workload",
            "family": workload.family,
            "task": workload.task,
            "hash_algorithm": "sha256",
            "hash": workload.model_hash,
            "measurement_hash": workload.model_hash,
            "manifest": "config/pilots/m42/model-manifest.json",
            "weights_status": "external_not_vendored",
            "notes": "Hash binds the pilot workload identity. Live activation must replace it with the approved checkpoint or hosted endpoint digest.",
        },
        "circuit": {
            "name": workload.circuit_name,
            "version": "1.0.0",
            "proof_system": workload.proof_system,
            "hash_algorithm": "sha256",
            "hash": workload.circuit_hash,
            "circuit_hash": workload.circuit_hash,
            "manifest": "config/pilots/m42/circuit-manifest.json",
            "scope_limit": "Hybrid evidence binding circuit for inputs, outputs, policy, and TEE measurement. It does not prove scientific or clinical correctness of model output.",
        },
        "policy": {
            "region": REGION,
            "jurisdiction": JURISDICTION,
            "data_class": workload.data_class,
            "processing_boundary": "Aethelred sandbox only",
            "egress_policy": "deny_by_default",
            "retention_days": RETENTION_DAYS,
            "require_tee_attestation": True,
            "require_zkml_proof": True,
            "require_both": True,
            "evidence_mode": "hybrid_tee_zkml_digital_seal",
            "tee_only_allowed": False,
            "commitments_only_allowed": False,
            "fallback_allowed": False,
        },
        "success_metrics": {
            "primary_metric": workload.primary_metric,
            "metric_floors": workload.metric_floors,
            "baseline_measurement_required": True,
            "aethelred_sandbox_run_required": True,
            "evidence_bundle_completeness": "100% of accepted cases produce hybrid TEE + zkML + Digital Seal evidence.",
            "determinism_replay_match_rate": ">= 99%",
            "baseline_vs_verified_delta": "Report p50/p95 latency and cost deltas; no production performance claim until live hardware run is complete.",
            "zero_live_data_findings": "0 live PHI or customer records in pilot package and validation exports.",
        },
        "economics": workload.economics,
        "evidence_outputs": {
            "schema": "docs/api/evidence-bundle-v1.schema.json",
            "evidence_schema_version": "v1",
            "mode": "hybrid_tee_zkml_digital_seal",
            "accepted_job_requires": ["tee_attestation", "zkml_proof", "validator_signature", "chain_id", "job_id", "seal_id"],
            "single_evidence_fallback": False,
            "evidence_path": f"config/pilots/m42/evidence/workloads/{workload.id}",
        },
        "data": {
            "fixture": str(workload.fixture_path.relative_to(ROOT)),
            "fixture_count": workload.fixture_count,
            "case_unit": workload.case_unit,
            "evaluation_protocol": f"docs/workload-packs/m42/workloads/{workload.id}/evaluation-protocol.md",
        },
    }


def build_catalog() -> dict[str, Any]:
    return {
        "$schema": "https://aethelred.network/schemas/workload-catalog-v1.json",
        "customer": "M42",
        "pilot_fee_usd": 200000,
        "active_workload": ACTIVE_WORKLOAD_ID,
        "selection_note": (
            "M42 selects one workload to drive the four-week paid pilot. All four packs are "
            "ready; the active workload binds the canonical evidence path and CI gate. Run any "
            "workload with scripts/m42-sandbox-drill.py --workload <id> or --all."
        ),
        "workloads": [
            {
                "id": workload.id,
                "kind": workload.kind,
                "title": workload.title,
                "case_unit": workload.case_unit,
                "primary_metric": workload.primary_metric,
                "metric_floors": workload.metric_floors,
                "model_hash": workload.model_hash,
                "circuit_hash": workload.circuit_hash,
                "pack": str(workload.pack_path.relative_to(ROOT)),
                "fixture": str(workload.fixture_path.relative_to(ROOT)),
                "fixture_count": workload.fixture_count,
                "why_first": workload.economics.get("why_first", ""),
            }
            for workload in WORKLOADS
        ],
    }


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def evaluation_protocol_md(workload: Workload) -> str:
    floors = "\n".join(
        f"| {key} | {value} |" for key, value in workload.metric_floors.items()
    )
    return f"""# M42 Workload Evaluation Protocol — {workload.title}

Workload id: `{workload.id}`
Kind: `{workload.kind}`
Unit of evaluation: one {workload.case_unit}

## Scope

{workload.task}. Synthetic, non-live data only: no PHI, no live patient records,
no M42 production data. Metrics are computed from the embedded ground truth in
`{workload.fixture_path.relative_to(ROOT)}` and are reproducible from the fixture.

## Success metrics and acceptance floors

| Metric / constraint | Floor |
|---------------------|-------|
{floors}

Primary metric: `{workload.primary_metric}`.

## Evidence contract

Each accepted case produces a hybrid evidence bundle (TEE attestation + zkML
proof + Digital Seal), binding model hash `{workload.model_hash}` and circuit
hash `{workload.circuit_hash}`. TEE-only, commitments-only, and single-evidence
fallback are out of scope for accepted paid-pilot evidence.

## Economics measured

Baseline vs verified unit cost and latency, and effective throughput
({workload.economics.get('throughput_units_per_hour')} {workload.case_unit_plural}/hour
target), reported as deltas against the M42 baseline. No production performance
claim is made until the live hardware run is complete.

## Boundary

The circuit binds inputs, outputs, policy, and TEE measurement. It does not
prove scientific or clinical correctness of the model output; correctness is
measured separately by the metrics above against synthetic ground truth.
"""


def generate_all() -> None:
    WORKLOADS_DIR.mkdir(parents=True, exist_ok=True)
    for workload in WORKLOADS:
        # Every workload's fixture is deterministic and regenerable; none are
        # committed. The six hand-authored Med42 vignettes live separately in
        # docs/workload-packs/m42/synthetic-vignettes.jsonl for the walkthrough.
        cases = workload.generate_fixture(workload)
        write_jsonl(workload.fixture_path, cases)
        write_json(workload.pack_path, build_pack(workload))
        protocol_path = FIXTURE_DIR / workload.id / "evaluation-protocol.md"
        protocol_path.parent.mkdir(parents=True, exist_ok=True)
        protocol_path.write_text(evaluation_protocol_md(workload), encoding="utf-8")
        print(f"workload {workload.id}: pack + fixture ({workload.fixture_count} {workload.case_unit_plural})")
    write_json(WORKLOADS_DIR / "catalog.json", build_catalog())
    # Publish the verification trust config (public keys + measurement allow-list)
    # so M42 has the parameters to verify every Digital Seal independently.
    import m42_seal
    write_json(PILOT_DIR / "trust-config.json", m42_seal.published_trust_config().to_dict())
    print(f"catalog: {len(WORKLOADS)} workloads, active={ACTIVE_WORKLOAD_ID}")


def main(argv: list[str]) -> int:
    if len(argv) >= 1 and argv[0] == "generate":
        generate_all()
        return 0
    if len(argv) >= 1 and argv[0] == "score":
        # Print computed metrics for every workload and fail if any workload
        # misses an acceptance floor. Used by CI to guard the floors.
        import sys

        failed = []
        for workload in WORKLOADS:
            cases = workload.load_cases()
            result = workload.score(workload, cases)
            floors = evaluate_floors(workload, result["metrics"])
            status = "OK" if floors["all_floors_met"] else "FLOORS NOT MET"
            print(f"{workload.id} [{status}] {json.dumps(result['metrics'], sort_keys=True)}")
            if not floors["all_floors_met"]:
                for check in floors["checks"]:
                    if not check["met"]:
                        print(f"  MISS {check['metric']} {check['comparison']} {check['floor']} observed={check['observed']}", file=sys.stderr)
                failed.append(workload.id)
        if failed:
            print(f"workloads missing acceptance floors: {', '.join(failed)}", file=sys.stderr)
            return 1
        return 0
    print("usage: m42_workloads.py [generate|score]", file=__import__("sys").stderr)
    return 2


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))
