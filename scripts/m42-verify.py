#!/usr/bin/env python3
"""Independent Digital Seal verifier — the tool M42 runs to check our evidence
themselves, trusting nothing but the published public keys.

For each workload's evidence directory it loads the published trust config
(validator Ed25519 + post-quantum XMSS public keys, attestation root public key,
approved measurements) and the batch proof, then:

  * verifies the validator HYBRID signature (Ed25519 + post-quantum XMSS) over the
    batch commitment, ONCE,
  * verifies the TEE attestation signature chain over the batch report-data root,
    ONCE,
  * verifies every seal by Merkle inclusion into those roots, plus (full mode)
    re-runs each Schnorr NIZK.

It reports throughput in both modes: the validator fast path (block verification:
signature + Merkle, thousands of seals/sec) and the full audit path (re-runs every
NIZK). `--demo-tamper` forges each part and shows the verifier rejecting it.

Exit 0 only if every seal verifies. Usage:
  scripts/m42-verify.py [--evidence-dir DIR] [--all] [--full] [--demo-tamper]
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import time
from pathlib import Path

import m42_crypto as crypto
import m42_seal as seal_mod

ROOT = Path(__file__).resolve().parents[1]
PILOT_EVIDENCE = ROOT / "config" / "pilots" / "m42" / "evidence"
CANONICAL_EXPORT = PILOT_EVIDENCE / "exports"
WORKLOAD_EVIDENCE = PILOT_EVIDENCE / "workloads"


def _load_trust(export_dir: Path) -> seal_mod.TrustConfig:
    path = export_dir / "trust-config.json"
    if path.exists():
        data = json.loads(path.read_text())
        return seal_mod.TrustConfig(
            validator_pubkey_hex=data["validator_pubkey"],
            validator_xmss_root_hex=data["validator_xmss_root"],
            attestation_root_pubkey_hex=data["attestation_root_pubkey"],
            allowed_measurements=set(data["allowed_measurements"]),
        )
    return seal_mod.published_trust_config()


def _verify_dir(export_dir: Path, full: bool, quiet: bool) -> tuple[int, int, float]:
    bundles = sorted(export_dir.glob("evidence-bundle-*.json"))
    batch_path = export_dir / "batch-proof.json"
    if not bundles or not batch_path.exists():
        return 0, 0, 0.0
    trust = _load_trust(export_dir)
    batch_proof = json.loads(batch_path.read_text())
    seals = [json.loads(p.read_text())["digital_seal"] for p in bundles]

    t0 = time.time()
    ok, summary = seal_mod.verify_evidence(seals, batch_proof, trust, full=full)
    dt = max(time.time() - t0, 1e-9)

    rel = export_dir.relative_to(ROOT)
    status = "OK" if ok else "FAIL"
    rate = len(seals) / dt
    if not quiet or not ok:
        mode = "full audit" if full else "validator fast path"
        print(f"[{status}] {rel}: {summary['verified_count']}/{summary['total']} seals verified "
              f"({mode}: {rate:,.0f} seals/sec)")
        if not ok:
            for sid, sok, checks, fresh in summary["seal_results"]:
                if not sok:
                    print(f"        FAILED {sid[:16]}: {[c.name for c in checks if not c.passed]} fresh={fresh}")
    return summary["verified_count"], summary["total"], dt


def demo_tamper() -> bool:
    print("\n=== Tamper demonstration (every forgery must be REJECTED) ===")
    trust = seal_mod.published_trust_config()
    seals = [seal_mod.build_seal(
        workload="genomic-variant-interpretation", model_hash="a" * 64, circuit_hash="b" * 64,
        input_value={"variant": f"BRCA1:c.{i}"}, output_value={"acmg": "pathogenic"},
        chain_id="aethelred-m42-pilot-1", timestamp="2026-06-12T00:00:00Z",
        nonce=f"demo-{i}", platform="sev-snp", zkml_tractable=True, seed_label=f"demo-{i}") for i in range(4)]
    batch = seal_mod.anchor_batch(seals, batch_index=900)
    ok, _ = seal_mod.verify_evidence(seals, batch, trust, full=True)
    print(f"  [{'OK' if ok else 'FAIL'}] untampered batch of {len(seals)} seals verifies")
    _, _, roots = seal_mod.verify_batch(batch, trust)

    def reject_seal(name, mutate):
        s = copy.deepcopy(seals[0]); mutate(s)
        bad, _ = seal_mod.verify_seal(s, roots, full=True)
        print(f"  [{'REJECTED' if not bad else 'ACCEPTED!!'}] {name}")
        return not bad

    def reject_batch(name, mutate):
        bp = copy.deepcopy(batch); mutate(bp)
        bad, _, _ = seal_mod.verify_batch(bp, trust)
        print(f"  [{'REJECTED' if not bad else 'ACCEPTED!!'}] {name}")
        return not bad

    results = [
        reject_seal("attacker flips the output (pathogenic -> benign) under the signed seal",
                    lambda s: s.update(output_commitment=crypto.commit({"acmg": "benign"}, b"forged"))),
        reject_seal("attacker substitutes the model hash", lambda s: s.update(model_hash="f" * 64)),
        reject_seal("attacker forges the Merkle inclusion proof",
                    lambda s: s["seal_inclusion_proof"]["siblings"].__setitem__(0, ["L", "00" * 32])),
        reject_seal("attacker forges the Schnorr zk proof",
                    lambda s: s["zk_proof"].update(response=format(int(s["zk_proof"]["response"], 16) + 1, "x"))),
        reject_batch("attacker forges the Ed25519 signature leg", lambda bp: bp["validator_hybrid_signature"].update(ed25519="00" * 64)),
        reject_batch("attacker forges the post-quantum XMSS signature leg",
                     lambda bp: bp["validator_hybrid_signature"]["pqc"]["wots_sig"].__setitem__(3, "00" * 32)),
        reject_batch("attacker re-signs the attestation with an untrusted root",
                     lambda bp: bp.update(attestation=crypto.make_attestation(
                         crypto.sha256(b"atk-enc"), crypto.sha256(b"atk-root"), "sev-snp",
                         next(iter(trust.allowed_measurements)), bp["batch_nonce"], bp["attestation_batch_root"]))),
        reject_batch("attacker tampers the signed batch root", lambda bp: bp.update(seal_batch_root="0" * 64)),
    ]
    all_rejected = all(results)
    print(f"\n  All {len(results)} forgeries rejected: {all_rejected}")
    return all_rejected


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Independently verify M42 Digital Seals.")
    parser.add_argument("--evidence-dir")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--full", action="store_true", help="Re-run every NIZK (deep audit) instead of the validator fast path.")
    parser.add_argument("--demo-tamper", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    dirs: list[Path] = []
    if args.evidence_dir:
        dirs.append(Path(args.evidence_dir))
    else:
        dirs.append(CANONICAL_EXPORT)
        if args.all and WORKLOAD_EVIDENCE.exists():
            dirs.extend(sorted(p / "exports" for p in WORKLOAD_EVIDENCE.iterdir() if (p / "exports").exists()))

    total_pass = total = 0
    total_dt = 0.0
    for d in dirs:
        p, t, dt = _verify_dir(d, args.full, args.quiet)
        total_pass += p
        total += t
        total_dt += dt

    if total:
        mode = "full audit" if args.full else "validator fast path"
        print(f"\nIndependent verification ({mode}): {total_pass}/{total} Digital Seals verified"
              + (f" — {total/total_dt:,.0f} seals/sec aggregate." if total_dt else "."))
    tamper_ok = demo_tamper() if args.demo_tamper else True
    if total == 0:
        print("No evidence found. Run: make m42-sandbox-drill-all", file=sys.stderr)
        return 2
    ok = total_pass == total and tamper_ok
    print("RESULT:", "ALL SEALS VERIFIED — no trust in Aethelred required." if ok else "VERIFICATION FAILED.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
