"""Tests for catalog integrity, registry registration, packs, and fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import m42_workloads as wl
from conftest import WORKLOAD_IDS

ROOT = Path(__file__).resolve().parents[2]
PILOT = ROOT / "config" / "pilots" / "m42"


EXPECTED_IDS = {
    "genomic-variant-interpretation",
    "med42-clinical-evaluation",
    "retrospective-radiology-ai",
    "drug-discovery-screening",
    "de-identification-attestation",
    "population-health-rwe",
    "biobank-gwas-prs",
    "digital-pathology-ai",
    "clinical-trial-matching",
    "med42-training-provenance",
}


def test_ten_workloads():
    assert len(wl.WORKLOADS) == 10
    assert {w.id for w in wl.WORKLOADS} == EXPECTED_IDS


def test_active_workload_in_catalog():
    assert wl.ACTIVE_WORKLOAD_ID in {w.id for w in wl.WORKLOADS}


def test_model_and_circuit_hashes_unique():
    model_hashes = [w.model_hash for w in wl.WORKLOADS]
    circuit_hashes = [w.circuit_hash for w in wl.WORKLOADS]
    assert len(set(model_hashes)) == len(model_hashes)
    assert len(set(circuit_hashes)) == len(circuit_hashes)


@pytest.mark.parametrize("wid", WORKLOAD_IDS)
def test_hash_is_lowercase_sha256(wid):
    w = wl.WORKLOAD_BY_ID[wid]
    for h in (w.model_hash, w.circuit_hash):
        assert len(h) == 64
        assert h == h.lower()
        int(h, 16)  # valid hex


@pytest.mark.parametrize("wid", WORKLOAD_IDS)
def test_every_workload_registered_active(wid):
    measurements = json.loads((PILOT / "registry" / "measurements.json").read_text())
    circuits = json.loads((PILOT / "registry" / "circuits.json").read_text())
    active_models = {e["hash"] for e in measurements["entries"] if e["status"] == "active"}
    active_circuits = {e["hash"] for e in circuits["entries"] if e["status"] == "active"}
    w = wl.WORKLOAD_BY_ID[wid]
    assert w.model_hash in active_models
    assert w.circuit_hash in active_circuits


def test_catalog_file_lists_all_workloads():
    catalog = json.loads((PILOT / "workloads" / "catalog.json").read_text())
    ids = {w["id"] for w in catalog["workloads"]}
    assert EXPECTED_IDS <= ids
    assert catalog["active_workload"] == wl.ACTIVE_WORKLOAD_ID


@pytest.mark.parametrize("wid", WORKLOAD_IDS)
def test_pack_file_complete(wid):
    pack = json.loads((PILOT / "workloads" / f"{wid}.json").read_text())
    assert pack["workload_id"] == wid
    assert pack["success_metrics"]["primary_metric"]
    assert pack["success_metrics"]["metric_floors"]
    assert pack["policy"]["require_both"] is True
    assert pack["policy"]["fallback_allowed"] is False
    assert pack["synthetic_status"]["phi_allowed"] is False


@pytest.mark.parametrize("wid", WORKLOAD_IDS)
def test_fixture_row_count_matches_catalog(wid):
    catalog = json.loads((PILOT / "workloads" / "catalog.json").read_text())
    entry = next(w for w in catalog["workloads"] if w["id"] == wid)
    fixture = ROOT / entry["fixture"]
    rows = [ln for ln in fixture.read_text().splitlines() if ln.strip()]
    assert len(rows) == entry["fixture_count"]


@pytest.mark.parametrize("wid", WORKLOAD_IDS)
def test_every_workload_defines_floors_and_economics(wid):
    w = wl.WORKLOAD_BY_ID[wid]
    assert w.metric_floors
    assert w.primary_metric
    assert w.economics.get("throughput_units_per_hour")
    assert "why_first" in w.economics


def test_generate_is_idempotent(tmp_path):
    # Regenerating must not change the committed packs/catalog.
    before = {}
    files = list((PILOT / "workloads").glob("*.json"))
    for f in files:
        before[f.name] = f.read_text()
    wl.generate_all()
    for f in files:
        assert f.read_text() == before[f.name], f"{f.name} changed on regenerate"


@pytest.mark.parametrize("wid", WORKLOAD_IDS)
def test_fixture_generation_is_deterministic(wid):
    # Fixtures are not committed; their value is reproducibility. Generating the
    # same workload twice must produce byte-identical cases.
    w = wl.WORKLOAD_BY_ID[wid]
    a = w.generate_fixture(w)
    b = w.generate_fixture(w)
    assert a == b
    assert len(a) == w.fixture_count


@pytest.mark.parametrize("wid", WORKLOAD_IDS)
def test_total_dataset_is_balanced(wid):
    # Every workload carries the same large case budget (100k total / 10).
    assert wl.WORKLOAD_BY_ID[wid].fixture_count == 10000
