#!/usr/bin/env python3
"""Enforce a fail-closed policy over govulncheck's JSON event stream.

govulncheck's text mode exits non-zero for every symbol-level finding, including
advisories whose published affected range is demonstrably stale. JSON mode lets
us retain that fail-closed behavior while narrowly reviewing exact
module/version/package combinations. Every temporary exception expires.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class ExceptionPolicy:
    module: str
    version: str
    packages: frozenset[str]
    expires: date
    reason: str


# These are not generic advisory suppressions. A module update, newly reached
# package, different advisory, or expiry date all fail the gate and require a
# fresh review. See docs/security/govulncheck-exceptions.md.
EXCEPTIONS: dict[str, ExceptionPolicy] = {
    "GO-2024-2584": ExceptionPolicy(
        module="github.com/cosmos/cosmos-sdk",
        version="v0.50.14",
        packages=frozenset(
            {
                "github.com/cosmos/cosmos-sdk/x/auth/vesting",
                "github.com/cosmos/cosmos-sdk/x/staking/keeper",
            }
        ),
        expires=date(2026, 10, 31),
        reason="official advisory patched the v0.50 line in v0.50.5",
    ),
    "GO-2024-3218": ExceptionPolicy(
        module="github.com/libp2p/go-libp2p-kad-dht",
        version="v0.37.1",
        packages=frozenset(
            {
                "github.com/libp2p/go-libp2p-kad-dht",
                "github.com/libp2p/go-libp2p-kad-dht/amino",
                "github.com/libp2p/go-libp2p-kad-dht/internal",
                "github.com/libp2p/go-libp2p-kad-dht/internal/config",
                "github.com/libp2p/go-libp2p-kad-dht/internal/metrics",
                "github.com/libp2p/go-libp2p-kad-dht/internal/net",
                "github.com/libp2p/go-libp2p-kad-dht/netsize",
                "github.com/libp2p/go-libp2p-kad-dht/pb",
                "github.com/libp2p/go-libp2p-kad-dht/qpeerset",
                "github.com/libp2p/go-libp2p-kad-dht/records",
                "github.com/libp2p/go-libp2p-kad-dht/rtrefresh",
            }
        ),
        expires=date(2026, 10, 31),
        reason="official advisory affects go-libp2p-kad-dht through v0.20.0",
    ),
    "GO-2026-5932": ExceptionPolicy(
        module="golang.org/x/crypto",
        version="v0.53.0",
        packages=frozenset(
            {
                "golang.org/x/crypto/openpgp/armor",
                "golang.org/x/crypto/openpgp/errors",
            }
        ),
        expires=date(2026, 10, 31),
        reason=(
            "Cosmos SDK v0.50.14 transitively uses only ASCII armor around "
            "AEAD-encrypted key material; operator-only key import/export has "
            "documented compensating controls"
        ),
    ),
}


def decode_event_stream(text: str) -> list[dict[str, Any]]:
    """Decode govulncheck's concatenated JSON objects."""
    decoder = json.JSONDecoder()
    events: list[dict[str, Any]] = []
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        event, offset = decoder.raw_decode(text, offset)
        if not isinstance(event, dict):
            raise ValueError("govulncheck stream contains a non-object event")
        events.append(event)
    return events


def symbol_findings(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return only findings govulncheck classified as source-reachable."""
    reachable: list[dict[str, Any]] = []
    for event in events:
        finding = event.get("finding")
        if not isinstance(finding, dict):
            continue
        trace = finding.get("trace")
        if (
            isinstance(trace, list)
            and trace
            and isinstance(trace[0], dict)
            and isinstance(trace[0].get("function"), str)
        ):
            reachable.append(finding)
    return reachable


def validate(
    events: list[dict[str, Any]], *, today: date
) -> tuple[list[str], dict[str, int]]:
    errors: list[str] = []
    allowed_counts: dict[str, int] = {}

    configs = [event["config"] for event in events if isinstance(event.get("config"), dict)]
    if len(configs) != 1:
        errors.append(f"expected exactly one govulncheck config event, found {len(configs)}")
    else:
        config = configs[0]
        if config.get("scan_level") != "symbol":
            errors.append(
                f"govulncheck scan_level must be symbol, found {config.get('scan_level')!r}"
            )
        if config.get("scan_mode") != "source":
            errors.append(
                f"govulncheck scan_mode must be source, found {config.get('scan_mode')!r}"
            )

    for finding in symbol_findings(events):
        advisory = finding.get("osv")
        trace = finding["trace"]
        vulnerable = trace[0]
        module = vulnerable.get("module")
        version = vulnerable.get("version")
        package = vulnerable.get("package")
        function = vulnerable.get("function")
        policy = EXCEPTIONS.get(advisory)

        label = f"{advisory} {module}@{version} {package}.{function}"
        if policy is None:
            errors.append(f"unreviewed reachable finding: {label}")
            continue
        if today > policy.expires:
            errors.append(
                f"expired exception ({policy.expires.isoformat()}): {label}"
            )
            continue
        if module != policy.module or version != policy.version:
            errors.append(
                "exception module/version mismatch: "
                f"{label}; expected {policy.module}@{policy.version}"
            )
            continue
        if package not in policy.packages:
            errors.append(
                f"exception does not cover newly reached package: {label}"
            )
            continue

        allowed_counts[advisory] = allowed_counts.get(advisory, 0) + 1

    return errors, allowed_counts


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} GOVULNCHECK_JSON", file=sys.stderr)
        return 2

    report_path = Path(argv[1])
    try:
        events = decode_event_stream(report_path.read_text(encoding="utf-8"))
        errors, allowed_counts = validate(events, today=date.today())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"govulncheck policy validation failed: {exc}", file=sys.stderr)
        return 1

    reachable_count = len(symbol_findings(events))
    print(f"govulncheck reachable symbol findings: {reachable_count}")
    for advisory, count in sorted(allowed_counts.items()):
        policy = EXCEPTIONS[advisory]
        print(
            f"  reviewed {advisory}: {count} symbol(s), "
            f"expires {policy.expires.isoformat()} — {policy.reason}"
        )

    if errors:
        print("govulncheck policy gate failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("govulncheck policy gate passed; no unreviewed reachable findings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
