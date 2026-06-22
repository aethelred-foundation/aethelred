"""Shared fixtures for the M42 workload-platform test suite.

Puts scripts/ on the path so the engine modules import cleanly, and scores
every workload once per session so the parametrized tests stay fast.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import m42_workloads as wl  # noqa: E402


WORKLOAD_IDS = [w.id for w in wl.WORKLOADS]


@pytest.fixture(scope="session", autouse=True)
def _ensure_fixtures():
    """Materialize every deterministic fixture once before the suite runs."""
    for workload in wl.WORKLOADS:
        workload.load_cases()


@pytest.fixture(scope="session")
def scored():
    """Map workload id -> (workload, cases, score result), computed once."""
    out = {}
    for workload in wl.WORKLOADS:
        cases = workload.load_cases()
        result = workload.score(workload, cases)
        out[workload.id] = (workload, cases, result)
    return out


@pytest.fixture(scope="session")
def workloads_module():
    return wl


# ---------------------------------------------------------------------------
# Random-dataset helpers shared by the property-based test families.
# ---------------------------------------------------------------------------

import m42_stats as st  # noqa: E402

# Seed grids used to parametrize property tests into the tens of thousands.
# Property tests run on small datasets (n~200), so a wide grid stays fast.
SEEDS_SMALL = list(range(60))
SEEDS_MED = list(range(400))
SEEDS_LARGE = list(range(400))
SEEDS_XL = list(range(600))


def make_binary_dataset(seed, n=200, separation=0.6, prevalence=0.4):
    """Deterministic (scores, labels) with a tunable signal, for property tests."""
    rng = st.DetRandom("dataset", seed, n, separation, prevalence)
    scores, labels = [], []
    for _ in range(n):
        y = 1 if rng.random() < prevalence else 0
        mu = 0.5 + separation / 2 if y else 0.5 - separation / 2
        scores.append(min(0.999, max(0.001, rng.gauss(mu, 0.18))))
        labels.append(y)
    # Guarantee both classes are present so AUROC/PR-AUC are defined.
    if sum(labels) == 0:
        labels[0] = 1
    if sum(labels) == len(labels):
        labels[0] = 0
    return scores, labels


def make_pvalues(seed, n=100, signal_fraction=0.2):
    """Deterministic p-values: a signal fraction near zero, the rest ~uniform."""
    rng = st.DetRandom("pvalues", seed, n)
    out = []
    for _ in range(n):
        if rng.random() < signal_fraction:
            out.append(rng.uniform(1e-9, 1e-4))
        else:
            out.append(rng.uniform(0.0, 1.0))
    return out
