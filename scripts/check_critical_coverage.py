#!/usr/bin/env python3
"""
Validate critical-path Go coverage for consensus evidence + verification readiness.

This script intentionally measures enterprise-critical consensus/verification guardrails
rather than aggregate repo coverage (which includes generated code and optional tooling).
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


CRITICAL_FUNCTIONS = [
    ("app/consensus_evidence.go", "requiredConsensusPower"),
    ("app/consensus_evidence.go", "parseInjectedConsensusTx"),
    ("app/consensus_evidence.go", "validateInjectedConsensusTxFormat"),
    ("app/consensus_evidence.go", "validateConsensusEvidenceThreshold"),
    ("app/consensus_evidence.go", "validateInjectedConsensusEvidenceAgainstCommit"),
    ("app/consensus_evidence.go", "AuditProposalConsensusEvidence"),
    ("app/consensus_evidence_api.go", "RunConsensusEvidenceAudit"),
    ("app/consensus_evidence_api.go", "decodeAuditTx"),
    ("app/consensus_evidence_api.go", "decodeAuditTxString"),
    ("app/consensus_evidence_handler.go", "ConsensusEvidenceAuditHandler"),
    ("x/verify/readiness.go", "String"),
    ("x/verify/readiness.go", "ValidateProductionReadiness"),
    ("x/verify/readiness.go", "validateOrchestratorConfig"),
    ("x/verify/readiness.go", "ValidateEndpointReachability"),
    ("x/verify/readiness.go", "isEndpointReachable"),
    ("x/verify/readiness.go", "endpointProbeURLs"),
]


def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, text=True, capture_output=True)
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(result.returncode)
    return result.stdout


def parse_cover_funcs(raw: str) -> dict[tuple[str, str], float]:
    # Example:
    # github.com/aethelred/aethelred/app/consensus_evidence.go:98: requiredConsensusPower 100.0%
    pattern = re.compile(r"^(?P<path>.+):\d+:\s+(?P<func>\S+)\s+(?P<pct>[\d.]+)%$")
    values: dict[tuple[str, str], float] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("total:"):
            continue
        match = pattern.match(line)
        if not match:
            continue
        path = match.group("path")
        func = match.group("func")
        pct = float(match.group("pct"))
        # keep by file suffix to avoid absolute/module prefix variance
        for wanted_file, wanted_func in CRITICAL_FUNCTIONS:
            if path.endswith(wanted_file) and func == wanted_func:
                values[(wanted_file, wanted_func)] = pct
                break
    return values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--threshold", type=float, default=95.0)
    parser.add_argument(
        "--coverprofile",
        default="/tmp/aethelred_critical.cover.out",
        help="Path to write the temporary coverage profile",
    )
    args = parser.parse_args()

    coverprofile = Path(args.coverprofile)
    run(
        [
            "go",
            "test",
            "./app",
            "./x/verify",
            "-coverprofile",
            str(coverprofile),
            "-count=1",
        ]
    )
    out = run(["go", "tool", "cover", f"-func={coverprofile}"])
    parsed = parse_cover_funcs(out)

    missing = [key for key in CRITICAL_FUNCTIONS if key not in parsed]
    if missing:
        sys.stderr.write("ERROR: missing coverage entries for critical functions:\n")
        for file_name, func_name in missing:
            sys.stderr.write(f"  - {file_name}:{func_name}\n")
        return 1

    total = 0.0
    for file_name, func_name in CRITICAL_FUNCTIONS:
        pct = parsed[(file_name, func_name)]
        total += pct
        print(f"{file_name}:{func_name} -> {pct:.1f}%")

    avg = total / len(CRITICAL_FUNCTIONS)
    print(f"\ncritical-path average coverage: {avg:.2f}% (threshold {args.threshold:.2f}%)")
    if avg < args.threshold:
        sys.stderr.write("ERROR: critical-path coverage below threshold\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
