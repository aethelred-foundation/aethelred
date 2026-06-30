#!/usr/bin/env python3
"""Finalize the public testnet genesis for launch.

The committed ``config/genesis/testnet-genesis.json`` is a template: it carries a
placeholder launch time, placeholder seed/peer node IDs, and (for cohort 1) a
disabled Ethereum bridge. Those values are intentionally NOT real in-repo because
they depend on launch-time infrastructure that only exists once seed/peer nodes
are provisioned.

This tool turns the template into a launch-ready genesis in a single, atomic,
reproducible step. It updates the genesis JSON, recomputes the checksum, and keeps
the checksum/image-tag references in the validator runbook and release-candidate
doc in lockstep — the exact consistency the public-testnet readiness gate enforces.

Typical launch-day invocation::

    python3 scripts/finalize-testnet-genesis.py \
        --launch-in 48h \
        --image-tag ghcr.io/aethelred-foundation/aethelred/aethelredd:testnet-v1.0.1 \
        --seed   <40hex>@seed1.testnet.aethelred.io:26656 \
        --seed   <40hex>@seed2.testnet.aethelred.io:26656 \
        --peer   <40hex>@peer1.testnet.aethelred.io:26656 \
        --peer   <40hex>@peer2.testnet.aethelred.io:26656 \
        --peer   <40hex>@peer3.testnet.aethelred.io:26656

Run with ``--check`` (default) to verify the result against
``validate-public-testnet-readiness.py`` immediately. Use ``--dry-run`` to preview
the changes without writing anything.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENESIS = ROOT / "config/genesis/testnet-genesis.json"
CHECKSUM = ROOT / "config/genesis/testnet-genesis.sha256"
CHECKSUM_REL = "config/genesis/testnet-genesis.json"
RUNBOOK = ROOT / "docs/TESTNET_VALIDATOR_RUNBOOK.md"
RC_DOC = ROOT / "docs/operations/testnet-release-candidate.md"
READINESS = ROOT / "scripts/validate-public-testnet-readiness.py"

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
IMAGE_PREFIX = "ghcr.io/aethelred-foundation/aethelred/aethelredd:"
MUTABLE_TAGS = ("latest", "stable")
NODE_ID_RE = re.compile(r"^[0-9a-fA-F]{40,}@[^:]+:\d+$")
ETH_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
DURATION_RE = re.compile(r"^(\d+)([smhd])$")
_DURATION_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    when = parser.add_mutually_exclusive_group()
    when.add_argument("--launch-time", help="absolute genesis time, ISO 8601 UTC (e.g. 2026-07-01T14:00:00Z)")
    when.add_argument("--launch-in", help="relative launch offset from now, e.g. 48h, 30m, 7d")
    parser.add_argument("--image-tag", help=f"validator image tag (must start with {IMAGE_PREFIX})")
    parser.add_argument("--seed", action="append", default=[], metavar="nodeID@host:port",
                        help="seed node entry; repeat for multiple. Replaces all existing seeds.")
    parser.add_argument("--peer", action="append", default=[], metavar="nodeID@host:port",
                        help="persistent peer entry; repeat for multiple. Replaces all existing peers.")
    bridge = parser.add_mutually_exclusive_group()
    bridge.add_argument("--bridge-contract", metavar="0x...", help="enable the Ethereum bridge with this contract address")
    bridge.add_argument("--disable-bridge", action="store_true", help="disable the Ethereum bridge (cohort-1 default)")
    parser.add_argument("--dry-run", action="store_true", help="print intended changes without writing files")
    parser.add_argument("--no-check", dest="check", action="store_false",
                        help="skip running the public-testnet readiness validator afterwards")
    parser.set_defaults(check=True)
    return parser.parse_args(argv)


def resolve_launch_time(args: argparse.Namespace) -> str | None:
    if args.launch_time:
        raw = args.launch_time.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(raw).astimezone(timezone.utc)
        except ValueError as exc:
            raise SystemExit(f"error: --launch-time is not valid ISO 8601: {exc}")
    elif args.launch_in:
        match = DURATION_RE.match(args.launch_in)
        if not match:
            raise SystemExit("error: --launch-in must look like 48h, 30m, 7d, or 90s")
        amount, unit = int(match.group(1)), match.group(2)
        dt = datetime.now(timezone.utc) + timedelta(**{_DURATION_UNITS[unit]: amount})
    else:
        return None
    if dt <= datetime.now(timezone.utc):
        raise SystemExit(f"error: resolved genesis time {dt.isoformat()} is not in the future")
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def validate_node_entries(entries: list[str], label: str) -> None:
    bad = [e for e in entries if not NODE_ID_RE.match(e)]
    if bad:
        raise SystemExit(f"error: invalid {label} entries (need <40hex>@host:port): {', '.join(bad)}")


def apply_changes(genesis: dict, launch_time: str | None, args: argparse.Namespace) -> list[str]:
    changes: list[str] = []

    if launch_time is not None:
        changes.append(f"genesis_time: {genesis.get('genesis_time')} -> {launch_time}")
        genesis["genesis_time"] = launch_time

    if args.image_tag is not None:
        if not args.image_tag.startswith(IMAGE_PREFIX):
            raise SystemExit(f"error: --image-tag must start with {IMAGE_PREFIX}")
        if any(args.image_tag.endswith(":" + t) or f":{t}" == args.image_tag[len(IMAGE_PREFIX) - 1:] for t in MUTABLE_TAGS):
            raise SystemExit("error: --image-tag must not use mutable latest/stable tags")
        genesis.setdefault("metadata", {})["image_tag"] = args.image_tag
        changes.append(f"image_tag -> {args.image_tag}")

    if args.seed:
        validate_node_entries(args.seed, "--seed")
        genesis["seed_nodes"] = list(args.seed)
        changes.append(f"seed_nodes -> {len(args.seed)} real entries")

    if args.peer:
        validate_node_entries(args.peer, "--peer")
        genesis["persistent_peers"] = list(args.peer)
        changes.append(f"persistent_peers -> {len(args.peer)} real entries")

    bridge = genesis.setdefault("bridge", {}).setdefault("ethereum", {})
    if args.disable_bridge:
        bridge["enabled"] = False
        changes.append("bridge.ethereum.enabled -> false (cohort-1 posture)")
    elif args.bridge_contract is not None:
        if not ETH_ADDRESS_RE.match(args.bridge_contract) or args.bridge_contract == ZERO_ADDRESS:
            raise SystemExit("error: --bridge-contract must be a non-zero 0x-prefixed 40-hex address")
        bridge["enabled"] = True
        bridge["contract_address"] = args.bridge_contract
        changes.append(f"bridge.ethereum -> enabled @ {args.bridge_contract}")

    return changes


def replace_in_doc(path: Path, replacements: dict[str, str], dry_run: bool) -> list[str]:
    if not path.exists():
        return [f"WARN: {path.relative_to(ROOT)} not found; skipped"]
    text = path.read_text(encoding="utf-8")
    notes: list[str] = []
    for old, new in replacements.items():
        if old and new and old != new and old in text:
            text = text.replace(old, new)
            notes.append(f"{path.relative_to(ROOT)}: {old[:16]}… -> {new[:16]}…")
    if not dry_run:
        path.write_text(text, encoding="utf-8")
    return notes


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if not GENESIS.exists():
        raise SystemExit(f"error: missing genesis template {GENESIS.relative_to(ROOT)}")

    genesis = json.loads(GENESIS.read_text(encoding="utf-8"))
    old_image = genesis.get("metadata", {}).get("image_tag", "")
    old_checksum = CHECKSUM.read_text(encoding="utf-8").split()[0] if CHECKSUM.exists() else ""

    launch_time = resolve_launch_time(args)
    changes = apply_changes(genesis, launch_time, args)
    if not changes:
        print("No changes requested. Pass --launch-time/--launch-in, --seed, --peer, "
              "--image-tag, or a bridge flag.", file=sys.stderr)
        return 2

    rendered = json.dumps(genesis, indent=2, ensure_ascii=False) + "\n"
    new_checksum = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    new_image = genesis.get("metadata", {}).get("image_tag", "")

    print("Planned genesis changes:")
    for change in changes:
        print(f"  - {change}")
    print(f"  - checksum: {old_checksum or '(none)'} -> {new_checksum}")

    doc_replacements = {old_checksum: new_checksum, old_image: new_image}
    if args.dry_run:
        print("\n[dry-run] no files written. Doc updates that would apply:")
        for path in (RUNBOOK, RC_DOC):
            for note in replace_in_doc(path, doc_replacements, dry_run=True):
                print(f"  - {note}")
        return 0

    GENESIS.write_text(rendered, encoding="utf-8")
    CHECKSUM.write_text(f"{new_checksum}  {CHECKSUM_REL}\n", encoding="utf-8")
    print(f"\nWrote {GENESIS.relative_to(ROOT)} and {CHECKSUM.relative_to(ROOT)}")
    for path in (RUNBOOK, RC_DOC):
        for note in replace_in_doc(path, doc_replacements, dry_run=False):
            print(f"  - {note}")

    if args.check and READINESS.exists():
        print("\nRunning public-testnet readiness gate...")
        result = subprocess.run([sys.executable, str(READINESS)], cwd=str(ROOT))
        return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
