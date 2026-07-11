#!/usr/bin/env python3
"""Adversarial demonstration — designed to be run by an M42 engineer.

Each row applies a real attack to genuine evidence and shows the verifier
REJECTS it. This is the pre‑agreed tamper‑resistance matrix from the pilot SOW.
A single "ACCEPTED" under attack is a failure and exits non‑zero.

    make m42-adversarial      # or: python3 scripts/m42-adversarial.py

The attacks map to the SOW acceptance criterion "tamper resistance":
substituted model · altered output · forged signature (classical + PQC) ·
forged inclusion proof · replayed nonce · tampered/untrusted attestation ·
mismatched workload · modified cost/energy factor.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import m42_crypto as crypto
import m42_energy as energy
import m42_seal as s

TRUST = s.published_trust_config()


def _batch(tag: str = "a", index: int = 42):
    # A batch of four real records (decoys give the Merkle proofs real siblings).
    # `tag`/`index` distinguish independent batches so a record from one cannot be
    # replayed into another.
    seals = [
        s.build_seal(
            workload="digital-pathology-ai", model_hash="a" * 64, circuit_hash="b" * 64,
            input_value={"slide": i, "batch": tag}, output_value={"malignant": (i % 2 == 0), "i": i},
            chain_id="aethelred-m42-pilot-1", timestamp="2026-07-11T00:00:00Z",
            nonce=f"nonce-{tag}-{i}", platform="sev-snp", zkml_tractable=True, seed_label=f"job-{tag}-{i}")
        for i in range(4)
    ]
    return seals, s.anchor_batch(seals, batch_index=index)


def _row(name: str, rejected: bool) -> bool:
    mark = "REJECTED  ok" if rejected else "ACCEPTED  ** FAIL **"
    print(f"  [{mark:>20}]  {name}")
    return rejected


def main() -> int:
    print("=" * 74)
    print("Aethelred adversarial demonstration — every forged record must be REJECTED")
    print("=" * 74)

    seals, bp = _batch()
    ok, _, roots = s.verify_batch(bp, TRUST)
    baseline_seal_ok, _ = s.verify_seal(seals[0], roots, full=True)
    print(f"  [{'VERIFIED  ok':>20}]  baseline: untampered batch + record verify")
    if not (ok and baseline_seal_ok):
        print("  baseline failed to verify — aborting")
        return 1

    results = []

    # --- record‑level attacks (verify against the real batch roots) ---
    def seal_attack(mutate):
        forged = copy.deepcopy(seals[0])
        mutate(forged)
        seal_ok, _ = s.verify_seal(forged, roots, full=True)
        return not seal_ok

    results.append(_row("substituted model identity",
                        seal_attack(lambda z: z.update(model_hash="f" * 64))))
    results.append(_row("altered output (malignant→benign)",
                        seal_attack(lambda z: z.update(output_commitment=crypto.commit({"malignant": False}, b"f")))))
    results.append(_row("forged Merkle inclusion proof",
                        seal_attack(lambda z: z["seal_inclusion_proof"]["siblings"].__setitem__(0, ["L", "00" * 32]))))
    results.append(_row("forged zero‑knowledge proof",
                        seal_attack(lambda z: z["zk_proof"].update(
                            response=format(int(z["zk_proof"]["response"], 16) + 1, "x")))))
    results.append(_row("weakened policy (fallback enabled)",
                        seal_attack(lambda z: z["policy"].update(fallback_allowed=True))))

    # --- batch‑level attacks (verify the whole batch) ---
    def batch_attack(mutate):
        forged = copy.deepcopy(bp)
        mutate(forged)
        b_ok, _, _ = s.verify_batch(forged, TRUST)
        return not b_ok

    results.append(_row("forged classical (Ed25519) signature leg",
                        batch_attack(lambda b: b["validator_hybrid_signature"].update(ed25519="00" * 64))))
    results.append(_row("forged post‑quantum (XMSS) signature leg",
                        batch_attack(lambda b: b["validator_hybrid_signature"]["pqc"]["wots_sig"].__setitem__(0, "00" * 32))))
    results.append(_row("tampered signed batch root",
                        batch_attack(lambda b: b.update(seal_batch_root="0" * 64))))
    results.append(_row("attestation re‑signed by an untrusted root",
                        batch_attack(lambda b: b.update(attestation=crypto.make_attestation(
                            crypto.sha256(b"e"), crypto.sha256(b"r"), "sev-snp",
                            next(iter(TRUST.allowed_measurements)), b["batch_nonce"], b["attestation_batch_root"])))))

    # --- replayed nonce (anti‑replay across a batch) ---
    a = s.build_seal(workload="digital-pathology-ai", model_hash="a" * 64, circuit_hash="b" * 64,
                     input_value={"slide": 1}, output_value={"malignant": True}, chain_id="aethelred-m42-pilot-1",
                     timestamp="2026-07-11T00:00:00Z", nonce="dup", platform="sev-snp", zkml_tractable=True, seed_label="a")
    b = s.build_seal(workload="digital-pathology-ai", model_hash="a" * 64, circuit_hash="b" * 64,
                     input_value={"slide": 2}, output_value={"malignant": False}, chain_id="aethelred-m42-pilot-1",
                     timestamp="2026-07-11T00:00:00Z", nonce="dup", platform="sev-snp", zkml_tractable=True, seed_label="b")
    rbp = s.anchor_batch([a, b], batch_index=7)
    replay_ok, _ = s.verify_evidence([a, b], rbp, TRUST, full=True)
    results.append(_row("replayed nonce (same nonce twice)", not replay_ok))

    # --- mismatched workload: a record from one batch verified under another
    # (a genuinely independent batch, distinct records and index) ---
    _, bp2 = _batch(tag="b", index=99)
    _, _, roots2 = s.verify_batch(bp2, TRUST)
    mism_ok, _ = s.verify_seal(seals[0], roots2, full=True)
    results.append(_row("record presented against a different batch", not mism_ok))

    # --- modified cost/energy factor (the measured record must not still match) ---
    m = energy.projected_measurement("nvidia-a100", 760 * 10000)
    receipt = energy.build_receipt("job-e", "aethelred-m42-pilot-validator", m, 10000)
    tampered = dict(receipt, avg_power_milliwatts=receipt["avg_power_milliwatts"] // 2)  # halve the power
    results.append(_row("modified energy/cost factor after commitment",
                        energy.receipt_hash(tampered) != receipt["receipt_hash"]))

    passed = sum(results)
    print("-" * 74)
    print(f"  {passed}/{len(results)} attacks rejected.")
    print("  An M42 engineer can re‑run this and mutate any field; forged evidence is refused.")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
