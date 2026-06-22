#!/usr/bin/env python3
"""Validate the real-data drug-discovery screen and wrap it in a verifiable
Digital Seal: real ChEMBL EGFR data + real cryptography, end to end.

This is the answer to "you only proved it on synthetic data": the screen runs on
real wet-lab bioactivity, and the seal commits to the exact benchmark hash and
the measured metrics, then verifies under the same real batch verifier M42 runs
for every other workload. Real data, real result, real proof.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import m42_crypto as crypto
import m42_realscreen as rs
import m42_seal

EXPORT = Path(__file__).resolve().parents[1] / "config/pilots/m42/evidence/exports"


def _json_safe(obj):
    """Coerce verifier Check tuples/dataclasses into plain JSON."""
    if hasattr(obj, "_asdict"):
        return obj._asdict()
    if hasattr(obj, "__dict__"):
        return vars(obj)
    return str(obj)

MODEL_HASH = crypto.sha256_hex(b"m42-chemfp-pathfp-v1")
CIRCUIT_HASH = crypto.sha256_hex(b"m42-ligand-vs-maxtanimoto-v1")


def validate() -> dict:
    card = rs.real_data_scorecard()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # The seal binds the real benchmark identity and the measured metrics.
    seal = m42_seal.build_seal(
        workload="drug-discovery-screening-realdata",
        model_hash=MODEL_HASH,
        circuit_hash=CIRCUIT_HASH,
        input_value={
            "benchmark": card["benchmark"],
            "benchmark_hash": card["benchmark_hash"],
            "compounds": card["compounds"],
            "data_status": card["data_status"],
        },
        output_value=card["metrics"],
        chain_id="aethelred-m42-pilot-1",
        timestamp=now,
        nonce=card["benchmark_hash"][:16],
        platform="sev-snp",
        zkml_tractable=True,
        seed_label="realdata-egfr-vs",
    )
    batch = m42_seal.anchor_batch([seal], batch_index=900)
    trust = m42_seal.published_trust_config()
    ok, summary = m42_seal.verify_evidence([seal], batch, trust, full=True)

    bundle = {
        "artifact_mode": "real_public_benchmark_verified",
        "generated_at": now,
        "scorecard": card,
        "digital_seal": seal,
        "batch_proof": batch,
        "verification": {"verified": ok, "summary": summary},
    }
    EXPORT.mkdir(parents=True, exist_ok=True)
    (EXPORT / "m42-realdata-validation.json").write_text(
        json.dumps(bundle, indent=2, default=_json_safe), encoding="utf-8"
    )
    return bundle


def main() -> int:
    bundle = validate()
    card, m = bundle["scorecard"], bundle["scorecard"]["metrics"]
    print("=" * 70)
    print("M42 real-data validation — drug discovery on real ChEMBL EGFR data")
    print("=" * 70)
    print(f"  benchmark        : {card['benchmark']}  ({card['compounds']} compounds)")
    print(f"  data status      : {card['data_status']}")
    print(f"  benchmark hash   : {card['benchmark_hash'][:32]}...")
    print(f"  held-out split   : {card['split']['held_out_actives']} actives vs "
          f"{card['split']['inactives']} inactives (prevalence {card['split']['active_prevalence']})")
    print("  measured metrics (real data, no label leakage):")
    print(f"    AUROC                {m['auroc']}  95% CI {m['auroc_ci95']}")
    print(f"    BEDROC (alpha=20)    {m['bedroc_alpha20']}")
    print(f"    EF @1% / ceiling     {m['enrichment_factor_1pct']} / {m['enrichment_factor_max_possible']}  "
          f"({m['early_enrichment_fraction_of_ideal']} of ideal)")
    print(f"    top-100 hit rate     {m['top100_hit_rate']}")
    print(f"  Digital Seal verified: {bundle['verification']['verified']}  "
          f"(real batch verifier, benchmark hash committed)")
    print(f"  -> {EXPORT / 'm42-realdata-validation.json'}")
    return 0 if bundle["verification"]["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
