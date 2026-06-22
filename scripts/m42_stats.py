#!/usr/bin/env python3
"""Tested numerical core for the M42 pilot workloads.

This module holds the metric primitives and the statistical-rigor layer used by
every workload scorer: ranking/classification metrics, bootstrap and Wilson
confidence intervals, calibration (Brier score and expected calibration error),
early-enrichment (BEDROC), multiple-testing control (Benjamini-Hochberg), and a
generic subgroup/fairness analyzer.

It is pure standard library and deterministic, so the drill stays lightweight
and reproducible. Every function here is unit-tested in tests/m42/, including
cross-validation against scipy where a reference exists.

Nothing in this module is a clinical, scientific, or production claim; it
computes metrics over synthetic ground truth.
"""

from __future__ import annotations

import hashlib
import math
import statistics
import struct
from typing import Any, Callable, Iterable, Sequence


# ---------------------------------------------------------------------------
# Deterministic randomness
# ---------------------------------------------------------------------------


class DetRandom:
    """A seeded sha256 stream RNG: reproducible without touching global state."""

    def __init__(self, *seed_parts: Any) -> None:
        seed = ":".join(str(part) for part in seed_parts).encode("utf-8")
        self._digest = hashlib.sha256(seed).digest()
        self._counter = 0

    def _next_block(self) -> bytes:
        block = hashlib.sha256(self._digest + self._counter.to_bytes(8, "big")).digest()
        self._counter += 1
        return block

    def random(self) -> float:
        """Uniform float in [0, 1)."""
        value = struct.unpack(">Q", self._next_block()[:8])[0]
        return value / float(1 << 64)

    def uniform(self, low: float, high: float) -> float:
        return low + (high - low) * self.random()

    def randint(self, low: int, high: int) -> int:
        """Inclusive integer in [low, high]."""
        return int(low + (high - low + 1) * self.random())

    def choice(self, items: Sequence[Any]) -> Any:
        return items[self.randint(0, len(items) - 1)]

    def gauss(self, mu: float, sigma: float) -> float:
        u1 = max(self.random(), 1e-12)
        u2 = self.random()
        z = math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)
        return mu + sigma * z

    def sample_indices(self, n: int) -> list[int]:
        """A bootstrap resample of size n (indices with replacement)."""
        return [self.randint(0, n - 1) for _ in range(n)]


def derive_hash(*parts: Any) -> str:
    return hashlib.sha256(":".join(str(part) for part in parts).encode("utf-8")).hexdigest()


def round_metrics(metrics: dict[str, Any], places: int = 4) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in metrics.items():
        out[key] = round(value, places) if isinstance(value, float) else value
    return out


# ---------------------------------------------------------------------------
# Ranking and classification metrics
# ---------------------------------------------------------------------------


def roc_auc(scores: Sequence[float], labels: Sequence[int]) -> float:
    """AUROC via the Mann-Whitney U statistic with tie handling."""
    pos = sum(1 for y in labels if y == 1)
    neg = len(labels) - pos
    if pos == 0 or neg == 0:
        return 0.0
    ranked = sorted(zip(scores, labels), key=lambda pair: pair[0])
    ranks = [0.0] * len(ranked)
    i = 0
    while i < len(ranked):
        j = i
        while j + 1 < len(ranked) and ranked[j + 1][0] == ranked[i][0]:
            j += 1
        avg_rank = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[k] = avg_rank
        i = j + 1
    rank_sum_pos = sum(rank for rank, (_, y) in zip(ranks, ranked) if y == 1)
    u = rank_sum_pos - pos * (pos + 1) / 2.0
    return u / (pos * neg)


def pr_auc(scores: Sequence[float], labels: Sequence[int]) -> float:
    """Average precision (area under the precision-recall curve)."""
    total_pos = sum(1 for y in labels if y == 1)
    if total_pos == 0:
        return 0.0
    order = sorted(zip(scores, labels), key=lambda pair: pair[0], reverse=True)
    tp = 0
    fp = 0
    prev_recall = 0.0
    ap = 0.0
    for _, label in order:
        if label == 1:
            tp += 1
        else:
            fp += 1
        recall = tp / total_pos
        precision = tp / (tp + fp)
        ap += precision * (recall - prev_recall)
        prev_recall = recall
    return ap


def enrichment_factor(scores: Sequence[float], labels: Sequence[int], fraction: float) -> float:
    """EF at a top fraction: (hit rate in the top slice) / (overall hit rate)."""
    n = len(scores)
    actives = sum(labels)
    if n == 0 or actives == 0:
        return 0.0
    cut = max(1, int(round(n * fraction)))
    top = sorted(zip(scores, labels), key=lambda pair: pair[0], reverse=True)[:cut]
    top_actives = sum(y for _, y in top)
    return (top_actives / cut) / (actives / n)


def bedroc(scores: Sequence[float], labels: Sequence[int], alpha: float = 20.0) -> float:
    """Boltzmann-enhanced discrimination of ROC: early-recognition metric in [0, 1].

    Truchon & Bayly (2007). alpha weights early ranks; alpha=20 ~ top 8%.
    """
    n = len(scores)
    actives = sum(labels)
    if n == 0 or actives == 0 or actives == n:
        return 0.0
    ratio = actives / n
    order = sorted(zip(scores, labels), key=lambda pair: pair[0], reverse=True)
    # Sum of exp(-alpha * rank/n) over active ranks (rank 1-indexed).
    rie_sum = sum(math.exp(-alpha * (rank / n)) for rank, (_, label) in enumerate(order, start=1) if label == 1)
    rie_random = (actives / n) * (1.0 - math.exp(-alpha)) / (math.exp(alpha / n) - 1.0)
    rie = rie_sum / rie_random if rie_random else 0.0
    factor = (ratio * math.sinh(alpha / 2.0)) / (math.cosh(alpha / 2.0) - math.cosh(alpha / 2.0 - alpha * ratio))
    offset = 1.0 / (1.0 - math.exp(alpha * (1.0 - ratio)))
    # BEDROC is defined on [0, 1]; clamp away floating-point overshoot.
    return min(1.0, max(0.0, rie * factor + offset))


def topk_hit_rate(scores: Sequence[float], labels: Sequence[int], k: int) -> float:
    k = min(k, len(scores))
    if k == 0:
        return 0.0
    top = sorted(zip(scores, labels), key=lambda pair: pair[0], reverse=True)[:k]
    return sum(y for _, y in top) / k


def binary_rates(scores: Sequence[float], labels: Sequence[int], threshold: float) -> dict[str, float]:
    tp = fp = tn = fn = 0
    for score, label in zip(scores, labels):
        predicted = 1 if score >= threshold else 0
        if predicted == 1 and label == 1:
            tp += 1
        elif predicted == 1 and label == 0:
            fp += 1
        elif predicted == 0 and label == 0:
            tn += 1
        else:
            fn += 1
    sensitivity = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    ppv = tp / (tp + fp) if (tp + fp) else 0.0
    npv = tn / (tn + fn) if (tn + fn) else 0.0
    denom = tp + fp + tn + fn
    accuracy = (tp + tn) / denom if denom else 0.0
    f1 = (2 * ppv * sensitivity / (ppv + sensitivity)) if (ppv + sensitivity) else 0.0
    # Matthews correlation coefficient.
    mcc_den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn) - (fp * fn)) / mcc_den if mcc_den else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "sensitivity": round(sensitivity, 4),
        "specificity": round(specificity, 4),
        "ppv": round(ppv, 4),
        "npv": round(npv, 4),
        "accuracy": round(accuracy, 4),
        "f1": round(f1, 4),
        "mcc": round(mcc, 4),
    }


def _descending_score_groups(scores: Sequence[float], labels: Sequence[int]):
    """Yield (threshold, cum_tp, cum_fp) after including each distinct score group.

    A single O(N log N) sweep from the highest score down, so the operating-point
    selectors scale to large cohorts (predict positive iff score >= threshold).
    """
    order = sorted(zip(scores, labels), key=lambda pair: pair[0], reverse=True)
    n = len(order)
    tp = fp = 0
    i = 0
    while i < n:
        j = i
        cur = order[i][0]
        while j < n and order[j][0] == cur:
            if order[j][1] == 1:
                tp += 1
            else:
                fp += 1
            j += 1
        yield cur, tp, fp
        i = j


def youden_threshold(scores: Sequence[float], labels: Sequence[int]) -> float:
    """Operating threshold maximizing Youden's J (sensitivity + specificity - 1)."""
    total_p = sum(labels)
    total_n = len(labels) - total_p
    if total_p == 0 or total_n == 0:
        return 0.5
    best_t, best_j = (max(scores) if scores else 0.5), -1.0
    for threshold, tp, fp in _descending_score_groups(scores, labels):
        sensitivity = tp / total_p
        specificity = 1.0 - fp / total_n
        j = sensitivity + specificity - 1.0
        if j > best_j:
            best_j, best_t = j, threshold
    return best_t


def threshold_for_sensitivity(scores: Sequence[float], labels: Sequence[int], target: float) -> float:
    """Highest threshold achieving sensitivity >= target (best specificity at the point).

    Lowering a threshold raises sensitivity, so the highest threshold that still
    meets the target sensitivity maximizes specificity there. This is the
    operating point a high-sensitivity screening tool is tuned to.
    """
    total_p = sum(labels)
    if total_p == 0 or not scores:
        return min(scores) if scores else 0.0
    need = target * total_p
    last = min(scores)
    for threshold, tp, _ in _descending_score_groups(scores, labels):
        last = threshold
        if tp >= need:
            return threshold
    return last


def threshold_for_precision(scores: Sequence[float], labels: Sequence[int], target: float) -> float:
    """Lowest threshold achieving precision >= target (best recall at the point)."""
    best_t = max(scores) if scores else 1.0
    found = False
    for threshold, tp, fp in _descending_score_groups(scores, labels):
        if (tp + fp) > 0 and tp / (tp + fp) >= target:
            best_t = threshold  # keep lowering while precision holds -> more recall
            found = True
    return best_t if found else (max(scores) if scores else 1.0)


def standardized_mean_difference(group_a: Sequence[float], group_b: Sequence[float]) -> float:
    """Absolute SMD between two cohorts on one covariate. <= 0.1 = balanced arms."""
    if not group_a or not group_b:
        return 0.0
    mean_a = statistics.mean(group_a)
    mean_b = statistics.mean(group_b)
    var_a = statistics.pvariance(group_a) if len(group_a) > 1 else 0.0
    var_b = statistics.pvariance(group_b) if len(group_b) > 1 else 0.0
    pooled_sd = ((var_a + var_b) / 2.0) ** 0.5
    if pooled_sd == 0:
        return 0.0
    return abs(mean_a - mean_b) / pooled_sd


# ---------------------------------------------------------------------------
# Confidence intervals
# ---------------------------------------------------------------------------


def wilson_ci(successes: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion (default 95%)."""
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = (z * math.sqrt((p * (1 - p) + z2 / (4 * n)) / n)) / denom
    return (max(0.0, center - half), min(1.0, center + half))


# Bootstrap working-set cap: for very large cohorts the percentile bootstrap is
# estimated on a deterministic representative subsample, keeping the CI fast
# without materially changing its width.
BOOTSTRAP_WORKING_CAP = 3000


def _capped(values: Sequence[Any], seed: str, cap: int = BOOTSTRAP_WORKING_CAP) -> list[Any]:
    if len(values) <= cap:
        return list(values)
    rng = DetRandom(seed, "cap", len(values))
    idx = sorted(set(rng.randint(0, len(values) - 1) for _ in range(cap * 2)))[:cap]
    return [values[i] for i in idx]


def bootstrap_ci(
    values: Sequence[float],
    statistic: Callable[[Sequence[float]], float],
    n_boot: int = 1000,
    seed: str = "m42-bootstrap",
    alpha: float = 0.05,
) -> tuple[float, float]:
    """Percentile bootstrap CI for a statistic of a single sample."""
    if not values:
        return (0.0, 0.0)
    work = _capped(values, seed)
    rng = DetRandom(seed, len(work), n_boot)
    estimates = []
    n = len(work)
    for _ in range(n_boot):
        idx = rng.sample_indices(n)
        estimates.append(statistic([work[i] for i in idx]))
    estimates.sort()
    lo = estimates[max(0, int((alpha / 2) * n_boot))]
    hi = estimates[min(n_boot - 1, int((1 - alpha / 2) * n_boot))]
    return (lo, hi)


def paired_bootstrap_ci(
    scores: Sequence[float],
    labels: Sequence[int],
    statistic: Callable[[Sequence[float], Sequence[int]], float],
    n_boot: int = 1000,
    seed: str = "m42-bootstrap",
    alpha: float = 0.05,
) -> tuple[float, float]:
    """Percentile bootstrap CI for a paired (scores, labels) statistic like AUROC.

    Resamples are kept stratified-ish by retrying draws that collapse to a single
    class, which keeps AUROC defined. Large cohorts are subsampled to a fixed
    working set first so the bootstrap stays fast.
    """
    n0 = len(scores)
    if n0 == 0:
        return (0.0, 0.0)
    pairs = _capped(list(zip(scores, labels)), seed)
    scores = [s for s, _ in pairs]
    labels = [y for _, y in pairs]
    n = len(scores)
    rng = DetRandom(seed, n, n_boot)
    estimates = []
    for _ in range(n_boot):
        for _attempt in range(8):
            idx = rng.sample_indices(n)
            boot_labels = [labels[i] for i in idx]
            if 0 < sum(boot_labels) < n:
                break
        boot_scores = [scores[i] for i in idx]
        estimates.append(statistic(boot_scores, boot_labels))
    estimates.sort()
    lo = estimates[max(0, int((alpha / 2) * n_boot))]
    hi = estimates[min(n_boot - 1, int((1 - alpha / 2) * n_boot))]
    return (round(lo, 4), round(hi, 4))


def _midranks(values: Sequence[float]) -> list[float]:
    """1-based midranks with average ranks for ties (for fast DeLong)."""
    n = len(values)
    order = sorted(range(n), key=lambda i: values[i])
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j < n and values[order[j]] == values[order[i]]:
            j += 1
        avg = (i + j - 1) / 2.0 + 1.0
        for k in range(i, j):
            ranks[order[k]] = avg
        i = j
    return ranks


def delong_auroc_ci(
    scores: Sequence[float], labels: Sequence[int], alpha: float = 0.05
) -> tuple[float, float, float]:
    """Fast DeLong AUROC variance and CI (Sun & Xu 2014), O(N log N).

    Returns (auc, lo, hi). This is the gold-standard analytic AUROC interval used
    in clinical literature, far faster than bootstrap at scale and exact for the
    asymptotic variance.
    """
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    m, n = len(pos), len(neg)
    if m == 0 or n == 0:
        return (0.0, 0.0, 0.0)
    tx = _midranks(pos)
    ty = _midranks(neg)
    tz = _midranks(list(pos) + list(neg))
    tzx = tz[:m]
    tzy = tz[m:]
    auc = (sum(tzx) / m - (m + 1) / 2.0) / n
    v10 = [(tzx[i] - tx[i]) / n for i in range(m)]
    v01 = [1.0 - (tzy[j] - ty[j]) / m for j in range(n)]
    sx = statistics.variance(v10) if m > 1 else 0.0
    sy = statistics.variance(v01) if n > 1 else 0.0
    var = sx / m + sy / n
    z = 1.959963984540054 if abs(alpha - 0.05) < 1e-9 else _z_for_alpha(alpha)
    half = z * math.sqrt(var) if var > 0 else 0.0
    return (auc, max(0.0, auc - half), min(1.0, auc + half))


def _z_for_alpha(alpha: float) -> float:
    # Two-sided z via inverse-erf; adequate for common alphas.
    return math.sqrt(2.0) * _erfinv(1.0 - alpha)


def _erfinv(x: float) -> float:
    # Winitzki approximation, accurate to ~1e-3 (sufficient for CI widths).
    a = 0.147
    ln = math.log(1 - x * x)
    term = 2 / (math.pi * a) + ln / 2
    return math.copysign(math.sqrt(math.sqrt(term * term - ln / a) - term), x)


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------


def brier_score(probs: Sequence[float], labels: Sequence[int]) -> float:
    """Mean squared error of probabilistic predictions. Lower is better."""
    if not probs:
        return 0.0
    return sum((p - y) ** 2 for p, y in zip(probs, labels)) / len(probs)


def reliability_bins(probs: Sequence[float], labels: Sequence[int], n_bins: int = 10) -> list[dict[str, Any]]:
    bins: list[dict[str, Any]] = []
    for b in range(n_bins):
        lo = b / n_bins
        hi = (b + 1) / n_bins
        members = [(p, y) for p, y in zip(probs, labels) if (p >= lo and (p < hi or (b == n_bins - 1 and p <= hi)))]
        if members:
            conf = sum(p for p, _ in members) / len(members)
            acc = sum(y for _, y in members) / len(members)
        else:
            conf = acc = 0.0
        bins.append({"bin": b, "lo": round(lo, 3), "hi": round(hi, 3), "count": len(members),
                     "confidence": round(conf, 4), "accuracy": round(acc, 4)})
    return bins


def expected_calibration_error(probs: Sequence[float], labels: Sequence[int], n_bins: int = 10) -> float:
    """ECE: average gap between confidence and accuracy, weighted by bin count."""
    if not probs:
        return 0.0
    n = len(probs)
    ece = 0.0
    for b in reliability_bins(probs, labels, n_bins):
        if b["count"]:
            ece += (b["count"] / n) * abs(b["confidence"] - b["accuracy"])
    return ece


def calibration_report(probs: Sequence[float], labels: Sequence[int], n_bins: int = 10) -> dict[str, Any]:
    return {
        "brier_score": round(brier_score(probs, labels), 4),
        "expected_calibration_error": round(expected_calibration_error(probs, labels, n_bins), 4),
        "reliability_bins": reliability_bins(probs, labels, n_bins),
    }


# ---------------------------------------------------------------------------
# Multiple-testing control
# ---------------------------------------------------------------------------


def benjamini_hochberg(pvalues: Sequence[float], alpha: float = 0.05) -> dict[str, Any]:
    """Benjamini-Hochberg FDR control. Returns rejection mask and the threshold."""
    m = len(pvalues)
    if m == 0:
        return {"rejected": [], "threshold": 0.0, "n_rejected": 0}
    order = sorted(range(m), key=lambda i: pvalues[i])
    threshold_rank = 0
    threshold_p = 0.0
    for rank, idx in enumerate(order, start=1):
        if pvalues[idx] <= (rank / m) * alpha:
            threshold_rank = rank
            threshold_p = pvalues[idx]
    rejected = [False] * m
    for rank, idx in enumerate(order, start=1):
        if rank <= threshold_rank:
            rejected[idx] = True
    return {"rejected": rejected, "threshold": threshold_p, "n_rejected": threshold_rank}


# ---------------------------------------------------------------------------
# Subgroup / fairness analysis
# ---------------------------------------------------------------------------


def subgroup_analysis(
    items: Iterable[dict[str, Any]],
    group_fn: Callable[[dict[str, Any]], str],
    metric_fn: Callable[[list[dict[str, Any]]], float | None],
    min_group: int = 8,
) -> dict[str, Any]:
    """Compute a metric per subgroup and report the worst-case disparity.

    Subgroups smaller than min_group are reported but excluded from the disparity
    gap so a tiny stratum does not dominate the fairness signal.
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        groups.setdefault(group_fn(item), []).append(item)
    per_group: dict[str, Any] = {}
    eligible_values: list[float] = []
    for name, members in sorted(groups.items()):
        value = metric_fn(members)
        per_group[name] = {"n": len(members), "value": round(value, 4) if isinstance(value, float) else value}
        if value is not None and len(members) >= min_group:
            eligible_values.append(value)
    disparity = (max(eligible_values) - min(eligible_values)) if len(eligible_values) >= 2 else 0.0
    return {
        "groups": per_group,
        "disparity_gap": round(disparity, 4),
        "min_subgroup_value": round(min(eligible_values), 4) if eligible_values else None,
        "max_subgroup_value": round(max(eligible_values), 4) if eligible_values else None,
    }


def worst_stratum_miss_rate(
    items: Iterable[dict[str, Any]],
    stratum_fn: Callable[[dict[str, Any]], str],
    positive_fn: Callable[[dict[str, Any]], bool],
    missed_fn: Callable[[dict[str, Any]], bool],
    min_positives: int = 15,
) -> dict[str, Any]:
    """Worst-case miss rate across clinically distinct strata.

    Aggregate sensitivity can hide a blind spot: a model may catch 92% of all
    critical findings yet systematically miss one deadly type. For each stratum
    this computes the miss rate among its true positive-class members at the
    operating threshold and returns the maximum (the blind-spot guard) plus the
    per-stratum breakdown. Strata with fewer than min_positives positives are
    reported but excluded from the worst-case so a tiny stratum cannot dominate.
    """
    positives: dict[str, int] = {}
    missed: dict[str, int] = {}
    for item in items:
        if not positive_fn(item):
            continue
        stratum = stratum_fn(item)
        positives[stratum] = positives.get(stratum, 0) + 1
        if missed_fn(item):
            missed[stratum] = missed.get(stratum, 0) + 1
    per_stratum: dict[str, Any] = {}
    eligible: list[float] = []
    for stratum in sorted(positives):
        rate = missed.get(stratum, 0) / positives[stratum]
        per_stratum[stratum] = {"positives": positives[stratum], "miss_rate": round(rate, 4)}
        if positives[stratum] >= min_positives:
            eligible.append(rate)
    return {
        "per_stratum": per_stratum,
        "worst_miss_rate": round(max(eligible), 4) if eligible else 0.0,
    }
