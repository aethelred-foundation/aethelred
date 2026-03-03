#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path("/Users/rameshtamilselvan/Downloads/AethelredMVP")
REGISTRY_PATH = ROOT / "docs/governance/repo-auditability-registry.json"


def _run(args, cwd=None):
    try:
        p = subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=True)
        return p.stdout.strip()
    except subprocess.CalledProcessError as e:
        return None


def _git_origin(repo_path: Path):
    return _run(["git", "-C", str(repo_path), "remote", "get-url", "origin"])


def _git_status_porcelain(repo_path: Path, paths):
    out = _run(["git", "-C", str(repo_path), "status", "--porcelain", "--"] + list(paths))
    return out.splitlines() if out else []


def _git_ls_files(repo_path: Path, rel_path: str):
    out = _run(["git", "-C", str(repo_path), "ls-files", "--", rel_path])
    return bool(out and rel_path in out.splitlines())


def _normalize_origin(url: str | None) -> str | None:
    if not url:
        return None
    if url.startswith("git@github.com:"):
        return url.replace("git@github.com:", "https://github.com/")
    return url


def validate(generate_matrix: bool, matrix_path: Path | None):
    registry = json.loads(REGISTRY_PATH.read_text())
    baseline = registry["baseline_required_files"]
    rows = []
    failures = []

    for repo in registry["repos"]:
        repo_name = repo["repo"]
        local_path = Path(repo["local_path"])
        role = repo.get("role", "")
        advanced_wfs = repo.get("advanced_expected_workflows", [])
        advanced_docs = repo.get("advanced_expected_docs", [])

        row = {
            "repo": repo_name,
            "role": role,
            "local_path": str(local_path),
            "exists": local_path.exists(),
            "git": (local_path / ".git").exists(),
            "origin_ok": False,
            "baseline_present": 0,
            "baseline_total": len(baseline),
            "baseline_missing": [],
            "baseline_tracked": 0,
            "advanced_present": 0,
            "advanced_total": len(advanced_wfs) + len(advanced_docs),
            "advanced_missing": [],
            "untracked_baseline_items": [],
            "dirty_baseline_paths": [],
        }

        if not row["exists"] or not row["git"]:
            failures.append(f"{repo_name}: local clone missing at {local_path}")
            rows.append(row)
            continue

        origin = _normalize_origin(_git_origin(local_path))
        expected_https = f"https://github.com/{repo_name}.git"
        row["origin_ok"] = origin == expected_https
        if not row["origin_ok"]:
            failures.append(f"{repo_name}: origin mismatch ({origin!r} != {expected_https!r})")

        for rel in baseline:
            p = local_path / rel
            if p.exists():
                row["baseline_present"] += 1
                if _git_ls_files(local_path, rel):
                    row["baseline_tracked"] += 1
                else:
                    row["untracked_baseline_items"].append(rel)
            else:
                row["baseline_missing"].append(rel)

        for rel in advanced_wfs + advanced_docs:
            if (local_path / rel).exists():
                row["advanced_present"] += 1
            else:
                row["advanced_missing"].append(rel)

        baseline_status = _git_status_porcelain(local_path, baseline)
        for line in baseline_status:
            if len(line) >= 4:
                row["dirty_baseline_paths"].append(line[3:])

        if row["baseline_missing"]:
            failures.append(
                f"{repo_name}: missing baseline files: {', '.join(row['baseline_missing'])}"
            )

        rows.append(row)

    if generate_matrix and matrix_path:
        matrix_path.write_text(render_matrix(registry, rows))

    if failures:
        print("[repo-auditability] validation failed")
        for f in failures:
            print(f" - {f}")
        return 1

    print("[repo-auditability] all local repo clones satisfy baseline auditability registry")
    for r in rows:
        print(
            f" - {r['repo']}: baseline {r['baseline_present']}/{r['baseline_total']}, "
            f"tracked {r['baseline_tracked']}/{r['baseline_total']}, "
            f"advanced {r['advanced_present']}/{r['advanced_total']}"
        )
    return 0


def render_matrix(registry, rows):
    lines = []
    lines.append("# AETH-MR-003 Repo Auditability Rollout Matrix")
    lines.append("")
    lines.append(f"Date: {registry.get('effective_date', 'unknown')}")
    lines.append(
        "Purpose: Track repo-local auditability/CI baseline presence and rollout readiness across the public Aethelred repos."
    )
    lines.append("")
    lines.append("Baseline required in every repo:")
    for f in registry["baseline_required_files"]:
        lines.append(f"- `{f}`")
    lines.append("")
    lines.append("| Repo | Role | Baseline | Tracked | Advanced | Push Readiness | Notes |")
    lines.append("|---|---|---:|---:|---:|---|---|")
    for r in rows:
        baseline = f"{r['baseline_present']}/{r['baseline_total']}"
        tracked = f"{r['baseline_tracked']}/{r['baseline_total']}"
        advanced = f"{r['advanced_present']}/{r['advanced_total']}"
        if not r["exists"] or not r["git"]:
            readiness = "blocked"
            notes = "missing local clone"
        elif r["baseline_missing"]:
            readiness = "implement"
            notes = "missing baseline files"
        elif r["untracked_baseline_items"]:
            readiness = "commit"
            notes = "baseline files exist but are untracked"
        else:
            readiness = "ready (push may require workflow-scope PAT)"
            notes = "baseline tracked locally"
        if not r["origin_ok"]:
            notes = (notes + "; " if notes else "") + "origin mismatch"
        if r["advanced_missing"]:
            notes = (notes + "; " if notes else "") + f"missing advanced: {len(r['advanced_missing'])}"
        lines.append(
            f"| `{r['repo']}` | `{r['role']}` | {baseline} | {tracked} | {advanced} | {readiness} | {notes} |"
        )
    lines.append("")
    lines.append("Notes:")
    lines.append("- `Tracked` means the baseline files are tracked in the local git clone (not just present on disk).")
    lines.append("- Workflow pushes may be rejected by GitHub if the token lacks `workflow` scope.")
    lines.append("- This matrix is generated from local clones using `scripts/validate-repo-auditability.py`.")
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-matrix", action="store_true", help="Write/update the rollout matrix markdown file")
    parser.add_argument(
        "--matrix-path",
        default=str(ROOT / "docs/audits/aeth-mr-003-repo-auditability-rollout-matrix.md"),
        help="Path to write matrix markdown (used with --write-matrix)",
    )
    args = parser.parse_args()

    rc = validate(args.write_matrix, Path(args.matrix_path) if args.write_matrix else None)
    sys.exit(rc)


if __name__ == "__main__":
    main()
