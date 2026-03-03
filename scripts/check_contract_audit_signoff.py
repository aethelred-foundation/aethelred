#!/usr/bin/env python3
"""Fail deployment preflight unless required external audits are formally signed off."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from dataclasses import dataclass


@dataclass
class AuditRow:
    audit_id: str
    auditor: str
    scope: str
    signed_ref: str
    signed_on: str
    status: str
    report: str


def parse_status_rows(status_path: pathlib.Path) -> list[AuditRow]:
    rows: list[AuditRow] = []
    for line in status_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue

        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 7:
            continue
        if cells[0] in {"ID", "---"}:
            continue
        if set(cells[0]) == {"-"}:
            continue

        report = cells[6].strip("` ")
        rows.append(
            AuditRow(
                audit_id=cells[0],
                auditor=cells[1],
                scope=cells[2],
                signed_ref=cells[3],
                signed_on=cells[4],
                status=cells[5],
                report=report,
            )
        )
    return rows


def report_has_signoff(report_path: pathlib.Path) -> bool:
    text = report_path.read_text(encoding="utf-8")
    return bool(
        re.search(r"(?im)^signed[- ]off\s*:\s*(yes|true|approved)\s*$", text)
        or re.search(r"(?im)^auditor-signature\s*:\s*\S+", text)
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--status",
        default="docs/audits/STATUS.md",
        help="Path to audit status tracker markdown file.",
    )
    parser.add_argument(
        "--scope-contains",
        action="append",
        default=[],
        help="(Deprecated) Scope token that must be present for an audit entry.",
    )
    parser.add_argument(
        "--required-scope",
        action="append",
        default=[],
        help=(
            "Scope token that must have at least one Completed audit row. "
            "Can be passed multiple times."
        ),
    )
    parser.add_argument(
        "--require-signed-report",
        action="store_true",
        help="Also require report content to contain Signed-Off metadata.",
    )
    args = parser.parse_args()

    status_path = pathlib.Path(args.status)
    if not status_path.exists():
        print(f"ERROR: missing status file: {status_path}", file=sys.stderr)
        return 1

    required_scopes = [*args.required_scope, *args.scope_contains]
    if not required_scopes:
        required_scopes = ["/contracts/ethereum"]

    rows = parse_status_rows(status_path)
    completed: list[AuditRow] = []
    for scope in required_scopes:
        scoped_rows = [r for r in rows if scope in r.scope]
        if not scoped_rows:
            print(
                f"ERROR: no audit rows found for scope token {scope!r} in {status_path}",
                file=sys.stderr,
            )
            return 1

        scoped_completed = [r for r in scoped_rows if r.status.strip().lower() == "completed"]
        if not scoped_completed:
            statuses = ", ".join(sorted({r.status for r in scoped_rows}))
            print(
                "ERROR: required audit scope has no completed signoff; "
                f"scope={scope!r}, statuses=[{statuses}] in {status_path}",
                file=sys.stderr,
            )
            return 1

        completed.extend(scoped_completed)

    repo_root = pathlib.Path.cwd()
    seen_audits: set[str] = set()
    for row in completed:
        if row.audit_id in seen_audits:
            continue
        seen_audits.add(row.audit_id)

        if not row.signed_ref or row.signed_ref.upper() == "TBD":
            print(
                f"ERROR: completed audit {row.audit_id} is missing Signed Ref",
                file=sys.stderr,
            )
            return 1
        if not row.signed_on or row.signed_on.upper() == "TBD":
            print(
                f"ERROR: completed audit {row.audit_id} is missing Signed On date",
                file=sys.stderr,
            )
            return 1
        if not row.report or row.report.upper() == "TBD":
            print(
                f"ERROR: completed audit {row.audit_id} is missing report path",
                file=sys.stderr,
            )
            return 1

        report_path = (repo_root / row.report).resolve()
        if not report_path.exists():
            print(
                f"ERROR: report for completed audit {row.audit_id} not found: {row.report}",
                file=sys.stderr,
            )
            return 1

        if args.require_signed_report and not report_has_signoff(report_path):
            print(
                f"ERROR: report {row.report} has no Signed-Off/Auditor-Signature metadata",
                file=sys.stderr,
            )
            return 1

    scopes_text = ", ".join(required_scopes)
    print(
        "OK: audit signoff gate passed for required scopes "
        f"[{scopes_text}] with {len(seen_audits)} completed audit row(s)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
