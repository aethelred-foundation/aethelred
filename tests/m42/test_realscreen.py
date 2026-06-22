"""Real-data drug-discovery: ChEMBL EGFR benchmark + ligand-based virtual screen.

These tests assert the benchmark is real (wet-lab labels), the fingerprint is a
sound similarity, and the screen is leakage-free and reproducible — the things a
scientific reviewer checks before trusting a non-circular result.
"""

from __future__ import annotations

import m42_chemfp as chemfp
import m42_realscreen as rs


# --- Fingerprint ----------------------------------------------------------

GEFITINIB = "COc1cc2ncnc(Nc3ccc(F)c(Cl)c3)c2cc1OCCCN1CCOCC1"
ERLOTINIB = "C#Cc1cccc(Nc2ncnc3cc(OCCOC)c(OCCOC)cc23)c1"


def test_tokenizer_handles_two_letter_and_bracket_atoms():
    toks = chemfp.tokenize_smiles("Cc1ccc(Cl)cc1[nH]Br")
    assert "Cl" in toks and "Br" in toks and "[nH]" in toks


def test_identical_smiles_tanimoto_is_one():
    fp = chemfp.fingerprint(GEFITINIB)
    assert chemfp.tanimoto(fp, fp) == 1.0


def test_different_molecules_are_partially_similar():
    a, b = chemfp.fingerprint(GEFITINIB), chemfp.fingerprint(ERLOTINIB)
    sim = chemfp.tanimoto(a, b)
    assert 0.0 < sim < 1.0  # share quinazoline scaffold but differ


def test_fingerprint_is_deterministic_across_calls():
    # FNV-1a hashing must be process-stable (unlike salted hash()).
    chemfp.fingerprint.cache_clear()
    a = set(chemfp.fingerprint(ERLOTINIB))
    chemfp.fingerprint.cache_clear()
    b = set(chemfp.fingerprint(ERLOTINIB))
    assert a == b


def test_empty_smiles_is_empty_fingerprint():
    assert chemfp.fingerprint("") == frozenset()
    assert chemfp.tanimoto(frozenset(), frozenset()) == 0.0


# --- Real benchmark -------------------------------------------------------


def test_benchmark_is_real_and_balanced_enough():
    rows = rs.load_benchmark()
    assert len(rows) > 500
    labels = {r["label"] for r in rows}
    assert labels == {0, 1}
    actives = sum(1 for r in rows if r["label"] == 1)
    assert actives > 100 and actives < len(rows)  # real, both classes present
    # Every row carries a real structure and an experimental potency.
    for r in rows[:50]:
        assert r["smiles"] and (r["ic50_nM"] is not None)


def test_benchmark_hash_is_stable():
    rows = rs.load_benchmark()
    assert rs.benchmark_hash(rows) == rs.benchmark_hash(list(reversed(rows)))


# --- Screen ---------------------------------------------------------------


def test_screen_is_leakage_free():
    rows = rs.load_benchmark()
    actives = [r for r in rows if r["label"] == 1]
    order = rs._shuffled_indices(len(actives), "egfr-vs")
    n_query = max(1, int(len(actives) * 0.3))
    query_mols = {actives[order[i]]["mol"] for i in range(n_query)}
    held_mols = {actives[order[i]]["mol"] for i in range(n_query, len(actives))}
    # The graded (held-out) actives must be disjoint from the query set.
    assert query_mols.isdisjoint(held_mols)


def test_screen_metrics_are_well_formed_on_real_data():
    result = rs.run_screen(rs.load_benchmark())
    m = result["metrics"]
    assert 0.0 <= m["auroc"] <= 1.0
    lo, hi = m["auroc_ci95"]
    assert lo <= m["auroc"] <= hi
    # EF can never exceed 1/prevalence; we report and respect that ceiling.
    assert m["enrichment_factor_1pct"] <= m["enrichment_factor_max_possible"] + 1e-9
    assert 0.0 <= m["early_enrichment_fraction_of_ideal"] <= 1.0
    assert 0.0 <= m["top100_hit_rate"] <= 1.0


def test_screen_is_reproducible():
    rows = rs.load_benchmark()
    a = rs.run_screen(rows, seed="fixed")["metrics"]
    b = rs.run_screen(rows, seed="fixed")["metrics"]
    assert a == b


def test_real_screen_clears_a_credible_bar():
    # A real ligand-based screen on real EGFR data should be clearly better than
    # random (AUROC > 0.7) with early recognition — else the benchmark or method
    # is broken. This is a real measurement, not an engineered target.
    m = rs.run_screen(rs.load_benchmark())["metrics"]
    assert m["auroc"] > 0.7
    assert m["bedroc_alpha20"] > 0.5


def test_scorecard_declares_real_data_provenance():
    card = rs.real_data_scorecard()
    assert card["data_status"] == "real_experimental_non_synthetic"
    assert card["provenance"]["source"] == "ChEMBL"
    assert card["not_for_clinical_use"] is True
    assert "benchmark_hash" in card


def test_realdata_result_binds_into_verifiable_seal():
    # Real data + real crypto: the screen result is committed in a Digital Seal
    # and verifies under the same batch verifier M42 runs for every workload;
    # tampering the committed metrics must break verification.
    import copy

    import m42_crypto as crypto
    import m42_seal

    card = rs.real_data_scorecard()
    seal = m42_seal.build_seal(
        workload="drug-discovery-screening-realdata",
        model_hash=crypto.sha256_hex(b"m42-chemfp-pathfp-v1"),
        circuit_hash=crypto.sha256_hex(b"m42-ligand-vs-maxtanimoto-v1"),
        input_value={"benchmark_hash": card["benchmark_hash"]},
        output_value=card["metrics"],
        chain_id="aethelred-m42-pilot-1",
        timestamp="2026-06-14T00:00:00Z",
        nonce=card["benchmark_hash"][:16],
        platform="sev-snp",
        zkml_tractable=True,
        seed_label="realdata-egfr-vs",
    )
    trust = m42_seal.published_trust_config()
    batch = m42_seal.anchor_batch([seal], batch_index=901)
    ok, summary = m42_seal.verify_evidence([seal], batch, trust, full=True)
    assert ok and summary["verified_count"] == 1

    _, _, roots = m42_seal.verify_batch(batch, trust)
    forged = copy.deepcopy(seal)
    forged["output_commitment"] = crypto.commit({"auroc": 0.999}, b"forge")
    seal_ok, _ = m42_seal.verify_seal(forged, roots, full=True)
    assert not seal_ok
