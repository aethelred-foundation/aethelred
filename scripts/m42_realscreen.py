#!/usr/bin/env python3
"""A real ligand-based virtual screen on real ChEMBL EGFR bioactivity data.

This replaces the synthetic drug-discovery fixture with a real, non-circular
benchmark: real compounds, real wet-lab IC50 ground truth (active <= 100 nM,
inactive >= 10 uM). A held-out evaluation prevents label leakage — the screen
queries with a subset of known actives and is graded on actives it never saw.

Every number here is a real measurement of a real method on real data, with a
DeLong confidence interval. The Digital Seal then commits to the exact benchmark
hash, so a reviewer can confirm the screen ran on this committed real dataset.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import m42_chemfp as chemfp
from m42_stats import (
    DetRandom,
    bedroc,
    delong_auroc_ci,
    enrichment_factor,
    topk_hit_rate,
)

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / "config/pilots/m42/realdata/egfr_chembl.jsonl"
PROVENANCE = ROOT / "config/pilots/m42/realdata/egfr_chembl.provenance.json"


def load_benchmark(path: Path = BENCHMARK) -> list[dict[str, Any]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def benchmark_hash(rows: list[dict[str, Any]]) -> str:
    """Stable SHA-256 over the (mol, label) pairs — the dataset the seal commits to."""
    canonical = ";".join(f"{r['mol']}:{r['label']}" for r in sorted(rows, key=lambda x: x["mol"]))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _shuffled_indices(n: int, seed: str) -> list[int]:
    rng = DetRandom(seed, n)
    idx = list(range(n))
    for i in range(n - 1, 0, -1):
        j = rng.randint(0, i)
        idx[i], idx[j] = idx[j], idx[i]
    return idx


def run_screen(rows: list[dict[str, Any]], query_frac: float = 0.3, seed: str = "egfr-vs") -> dict[str, Any]:
    """Ligand-based screen with a held-out split. Scores library compounds by max
    Tanimoto similarity to the query actives, then grades on held-out actives vs
    real inactives.
    """
    actives = [r for r in rows if r["label"] == 1]
    inactives = [r for r in rows if r["label"] == 0]
    order = _shuffled_indices(len(actives), seed)
    n_query = max(1, int(len(actives) * query_frac))
    query = [actives[order[i]] for i in range(n_query)]
    held = [actives[order[i]] for i in range(n_query, len(actives))]
    library = held + inactives

    query_fps = [chemfp.fingerprint(a["smiles"]) for a in query]
    scores: list[float] = []
    labels: list[int] = []
    for compound in library:
        fp = chemfp.fingerprint(compound["smiles"])
        best = 0.0
        for qf in query_fps:
            s = chemfp.tanimoto(fp, qf)
            if s > best:
                best = s
        scores.append(best)
        labels.append(compound["label"])

    auc, lo, hi = delong_auroc_ci(scores, labels)
    prevalence = sum(labels) / len(labels)
    ef1 = enrichment_factor(scores, labels, 0.01)
    ef_max = round(1.0 / prevalence, 4) if prevalence else 0.0  # EF is bounded by 1/prevalence
    return {
        "scores": scores,
        "labels": labels,
        "metrics": {
            "auroc": round(auc, 4),
            "auroc_ci95": [round(lo, 4), round(hi, 4)],
            "enrichment_factor_1pct": round(ef1, 4),
            "enrichment_factor_5pct": round(enrichment_factor(scores, labels, 0.05), 4),
            "enrichment_factor_max_possible": ef_max,
            "early_enrichment_fraction_of_ideal": round(ef1 / ef_max, 4) if ef_max else 0.0,
            "bedroc_alpha20": round(bedroc(scores, labels, 20.0), 4),
            "top100_hit_rate": round(topk_hit_rate(scores, labels, 100), 4),
        },
        "split": {
            "query_actives": len(query),
            "held_out_actives": len(held),
            "inactives": len(inactives),
            "library_size": len(library),
            "active_prevalence": round(len(held) / len(library), 4),
        },
    }


def real_data_scorecard() -> dict[str, Any]:
    rows = load_benchmark()
    provenance = json.loads(PROVENANCE.read_text(encoding="utf-8")) if PROVENANCE.exists() else {}
    result = run_screen(rows)
    return {
        "artifact_mode": "real_public_benchmark",
        "data_status": "real_experimental_non_synthetic",
        "benchmark": "ChEMBL EGFR (CHEMBL203) IC50 bioactivity",
        "benchmark_hash": benchmark_hash(rows),
        "compounds": len(rows),
        "provenance": provenance,
        "method": "ligand-based virtual screen; max-Tanimoto to held-out query actives; pure-Python path fingerprint",
        "evaluation": "held-out actives never seen by the query set (no label leakage)",
        "metrics": result["metrics"],
        "split": result["split"],
        "not_for_clinical_use": True,
        "honesty": (
            "Data and labels are real wet-lab IC50 from ChEMBL — not synthetic. The "
            "fingerprint is a dependency-free baseline (not RDKit Morgan); the metrics "
            "are a real measurement of that baseline on real data with a DeLong CI."
        ),
    }


if __name__ == "__main__":
    import sys
    json.dump(real_data_scorecard(), sys.stdout, indent=2)
    print()
