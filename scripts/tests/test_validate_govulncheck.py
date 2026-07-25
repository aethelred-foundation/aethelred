#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import sys
import unittest
from datetime import date
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "validate_govulncheck.py"
SPEC = importlib.util.spec_from_file_location("validate_govulncheck", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def config_event() -> dict:
    return {"config": {"scan_level": "symbol", "scan_mode": "source"}}


def finding_event(
    advisory: str,
    module: str,
    version: str,
    package: str,
    *,
    function: str | None = "Run",
) -> dict:
    frame = {"module": module, "version": version, "package": package}
    if function is not None:
        frame["function"] = function
    return {"finding": {"osv": advisory, "trace": [frame]}}


class GovulncheckPolicyTests(unittest.TestCase):
    def test_decodes_concatenated_json(self) -> None:
        events = MODULE.decode_event_stream('{"config": {}}\n{"finding": {}}\n')
        self.assertEqual(len(events), 2)

    def test_exact_reviewed_finding_passes(self) -> None:
        events = [
            config_event(),
            finding_event(
                "GO-2024-2584",
                "github.com/cosmos/cosmos-sdk",
                "v0.50.14",
                "github.com/cosmos/cosmos-sdk/x/staking/keeper",
            ),
        ]
        errors, counts = MODULE.validate(events, today=date(2026, 7, 25))
        self.assertEqual(errors, [])
        self.assertEqual(counts, {"GO-2024-2584": 1})

    def test_unknown_reachable_finding_fails(self) -> None:
        events = [
            config_event(),
            finding_event(
                "GO-2099-0001", "example.invalid/module", "v1.0.0", "example.invalid/pkg"
            ),
        ]
        errors, _ = MODULE.validate(events, today=date(2026, 7, 25))
        self.assertTrue(any("unreviewed reachable finding" in error for error in errors))

    def test_version_drift_fails(self) -> None:
        events = [
            config_event(),
            finding_event(
                "GO-2024-3218",
                "github.com/libp2p/go-libp2p-kad-dht",
                "v0.38.0",
                "github.com/libp2p/go-libp2p-kad-dht",
            ),
        ]
        errors, _ = MODULE.validate(events, today=date(2026, 7, 25))
        self.assertTrue(any("module/version mismatch" in error for error in errors))

    def test_new_package_fails(self) -> None:
        events = [
            config_event(),
            finding_event(
                "GO-2026-5932",
                "golang.org/x/crypto",
                "v0.53.0",
                "golang.org/x/crypto/openpgp",
            ),
        ]
        errors, _ = MODULE.validate(events, today=date(2026, 7, 25))
        self.assertTrue(any("newly reached package" in error for error in errors))

    def test_expired_exception_fails(self) -> None:
        events = [
            config_event(),
            finding_event(
                "GO-2024-2584",
                "github.com/cosmos/cosmos-sdk",
                "v0.50.14",
                "github.com/cosmos/cosmos-sdk/x/staking/keeper",
            ),
        ]
        errors, _ = MODULE.validate(events, today=date(2026, 11, 1))
        self.assertTrue(any("expired exception" in error for error in errors))

    def test_package_only_finding_is_not_source_reachable(self) -> None:
        events = [
            config_event(),
            finding_event(
                "GO-2099-0001",
                "example.invalid/module",
                "v1.0.0",
                "example.invalid/pkg",
                function=None,
            ),
        ]
        errors, counts = MODULE.validate(events, today=date(2026, 7, 25))
        self.assertEqual(errors, [])
        self.assertEqual(counts, {})


if __name__ == "__main__":
    unittest.main()
