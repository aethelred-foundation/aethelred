#!/usr/bin/env python3
"""Validate public testnet launch readiness without external network calls."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GENESIS = ROOT / "config/genesis/testnet-genesis.json"
CHECKSUM = ROOT / "config/genesis/testnet-genesis.sha256"
AUDIT_STATUS = ROOT / "docs/audits/STATUS.md"
RUNBOOK = ROOT / "docs/TESTNET_VALIDATOR_RUNBOOK.md"
RC_DOC = ROOT / "docs/operations/testnet-release-candidate.md"

CHAIN_ID = "aethelred-testnet-1"
RELEASE_BRANCH = "release/testnet-v1.0"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
REQUIRED_AUDIT_SCOPES = ("/contracts/ethereum", "Consensus + vote extensions")
MUTABLE_TAGS = {":latest", ":stable"}
NODE_ID_RE = re.compile(r"^[0-9a-fA-F]{40,}@[^:]+:\d+$")


def git_branch() -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "--abbrev-ref", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_time(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized).astimezone(timezone.utc)


def extract_first(pattern: str, text: str) -> str:
    match = re.search(pattern, text)
    return match.group(1).strip() if match else ""


def audit_scope_completed(status_text: str, scope: str) -> bool:
    for line in status_text.splitlines():
        if f"| {scope} |" in line:
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            return "Completed" in cells
    return False


def main() -> int:
    errors: list[str] = []
    warnings: list[str] = []

    if not GENESIS.exists():
        errors.append(f"missing genesis file: {GENESIS.relative_to(ROOT)}")
    if not CHECKSUM.exists():
        errors.append(f"missing checksum file: {CHECKSUM.relative_to(ROOT)}")
    if errors:
        return report(errors, warnings)

    genesis = json.loads(GENESIS.read_text())
    checksum_line = CHECKSUM.read_text().strip()
    checksum_parts = checksum_line.split()
    expected_hash = checksum_parts[0] if checksum_parts else ""
    expected_path = checksum_parts[1] if len(checksum_parts) > 1 else ""
    actual_hash = sha256(GENESIS)

    if expected_hash != actual_hash:
        errors.append(
            f"checksum mismatch for {GENESIS.relative_to(ROOT)}: "
            f"expected {expected_hash}, got {actual_hash}"
        )
    if expected_path != "config/genesis/testnet-genesis.json":
        errors.append(
            "checksum file must use repo-root relative path "
            "`config/genesis/testnet-genesis.json`"
        )

    if genesis.get("chain_id") != CHAIN_ID:
        errors.append(f"chain_id must be {CHAIN_ID!r}")
    if genesis.get("metadata", {}).get("network_type") != "testnet":
        errors.append("metadata.network_type must be 'testnet'")
    if genesis.get("token", {}).get("symbol") != "tAETHEL":
        errors.append("token.symbol must be 'tAETHEL'")

    image_tag = genesis.get("metadata", {}).get("image_tag", "")
    if not image_tag.startswith("ghcr.io/aethelred-foundation/aethelred/aethelredd:"):
        errors.append("metadata.image_tag must use the canonical GHCR validator image")
    if any(image_tag.endswith(tag) or tag in image_tag for tag in MUTABLE_TAGS):
        errors.append("metadata.image_tag must not use mutable latest/stable tags")

    # Post-quantum cryptography posture: the public testnet must declare and run
    # real hybrid PQC (never the simulated path), backed by circl with secp256k1.
    pqc = genesis.get("metadata", {}).get("pqc", {})
    if not pqc:
        errors.append("metadata.pqc posture block is missing; declare mode/backend/curve")
    else:
        if pqc.get("mode") not in ("hybrid", "production"):
            errors.append(
                f"metadata.pqc.mode must be 'hybrid' or 'production', got {pqc.get('mode')!r} "
                "(the simulated PQC path must never ship to a public testnet)"
            )
        if pqc.get("signature_backend") != "cloudflare-circl":
            errors.append("metadata.pqc.signature_backend must be 'cloudflare-circl' (real ML-DSA)")
        if pqc.get("classical_curve") != "secp256k1":
            errors.append("metadata.pqc.classical_curve must be 'secp256k1'")

    try:
        genesis_time = parse_time(genesis["genesis_time"])
        if genesis_time <= datetime.now(timezone.utc):
            errors.append(
                f"genesis_time {genesis['genesis_time']} is in the past; "
                "publish a fresh genesis before public onboarding"
            )
    except Exception as exc:
        errors.append(f"genesis_time is not parseable: {exc}")

    bridge = genesis.get("bridge", {}).get("ethereum", {})
    if bridge.get("enabled") is True and bridge.get("contract_address") == ZERO_ADDRESS:
        errors.append("bridge.ethereum.contract_address is zero while bridge is enabled")

    for field in ("seed_nodes", "persistent_peers"):
        entries = genesis.get(field, [])
        if not entries:
            errors.append(f"{field} must not be empty")
            continue
        invalid = [entry for entry in entries if not NODE_ID_RE.match(entry)]
        if invalid:
            errors.append(
                f"{field} must use real nodeID@host:port values; invalid entries: {', '.join(invalid)}"
            )

    runbook_text = RUNBOOK.read_text() if RUNBOOK.exists() else ""
    rc_text = RC_DOC.read_text() if RC_DOC.exists() else ""
    runbook_image = extract_first(r"\*\*Image Tag:\*\*\s*`([^`]+)`", runbook_text)
    rc_image = extract_first(r"\*\*Image Tag:\*\*\s*`([^`]+)`", rc_text)
    if runbook_image and runbook_image != image_tag:
        errors.append(f"runbook image tag {runbook_image!r} does not match genesis {image_tag!r}")
    if rc_image and rc_image != image_tag:
        errors.append(f"release-candidate image tag {rc_image!r} does not match genesis {image_tag!r}")
    if actual_hash and actual_hash not in runbook_text:
        errors.append("testnet validator runbook does not contain the current genesis checksum")
    if actual_hash and actual_hash not in rc_text:
        errors.append("testnet release candidate doc does not contain the current genesis checksum")

    audit_text = AUDIT_STATUS.read_text() if AUDIT_STATUS.exists() else ""
    if os.getenv("AETHELRED_PUBLIC_TESTNET_AUDIT_WAIVER") != "1":
        for scope in REQUIRED_AUDIT_SCOPES:
            if not audit_scope_completed(audit_text, scope):
                errors.append(
                    f"required audit scope is not completed: {scope}; "
                    "set AETHELRED_PUBLIC_TESTNET_AUDIT_WAIVER=1 only with a signed launch waiver"
                )
    else:
        warnings.append("audit completion gate bypassed by AETHELRED_PUBLIC_TESTNET_AUDIT_WAIVER=1")

    branch = git_branch()
    if branch != RELEASE_BRANCH:
        warnings.append(
            f"running on {branch!r}; final public launch validation must run on {RELEASE_BRANCH!r}"
        )

    return report(errors, warnings)


def report(errors: list[str], warnings: list[str]) -> int:
    for warning in warnings:
        print(f"[WARN] {warning}")
    if errors:
        print("Public testnet readiness validation failed:")
        for error in errors:
            print(f" - {error}")
        return 1
    print("Public testnet readiness validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
