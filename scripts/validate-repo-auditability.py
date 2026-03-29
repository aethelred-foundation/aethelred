#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
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


def _repo_slug_from_origin(url: str | None) -> str | None:
    normalized = _normalize_origin(url)
    if not normalized:
        return None
    if normalized.startswith("https://github.com/"):
        slug = normalized.removeprefix("https://github.com/")
        if slug.endswith(".git"):
            slug = slug[:-4]
        return slug
    return None


def _dedupe_paths(paths):
    seen = set()
    result = []
    for p in paths:
        if not p:
            continue
        key = str(p)
        if key in seen:
            continue
        seen.add(key)
        result.append(p)
    return result


def _candidate_local_paths(repo_entry: dict, current_repo_slug: str | None):
    repo_name = repo_entry["repo"]
    repo_tail = repo_name.split("/")[-1]
    candidates = []

    configured = repo_entry.get("local_path")
    if configured:
        candidates.append(Path(configured).expanduser())

    if current_repo_slug and repo_name == current_repo_slug:
        candidates.append(ROOT)

    env_base = os.getenv("AETHELRED_LOCAL_REPO_BASE")
    if env_base:
        candidates.append(Path(env_base).expanduser() / repo_tail)

    # Useful for local multi-repo checkouts without baking workstation paths into the registry.
    if os.getenv("CI") != "true" and os.getenv("AETHELRED_AUDITABILITY_SKIP_SIBLINGS") != "1":
        candidates.append(ROOT.parent / repo_tail)
    return _dedupe_paths(candidates)


def _resolve_local_repo_path(repo_entry: dict, current_repo_slug: str | None):
    for candidate in _candidate_local_paths(repo_entry, current_repo_slug):
        if candidate.exists() and (candidate / ".git").exists():
            return candidate
    return None


def validate(generate_matrix: bool, matrix_path: Path | None):
    registry = json.loads(REGISTRY_PATH.read_text())
    baseline = registry["baseline_required_files"]
    current_repo_slug = _repo_slug_from_origin(_git_origin(ROOT))
    rows = []
    failures = []
    current_repo_evaluated = False

    for repo in registry["repos"]:
        repo_name = repo["repo"]
        local_path = _resolve_local_repo_path(repo, current_repo_slug)
        role = repo.get("role", "")
        advanced_wfs = repo.get("advanced_expected_workflows", [])
        advanced_docs = repo.get("advanced_expected_docs", [])
        evaluated = local_path is not None

        row = {
            "repo": repo_name,
            "role": role,
            "local_path": str(local_path) if local_path else "",
            "exists": bool(local_path and local_path.exists()),
            "git": bool(local_path and (local_path / ".git").exists()),
            "origin_ok": None,
            "evaluated": evaluated,
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

        if not evaluated:
            if current_repo_slug and repo_name == current_repo_slug:
                failures.append(f"{repo_name}: current repo checkout could not be resolved")
            rows.append(row)
            continue

        if repo_name == current_repo_slug:
            current_repo_evaluated = True

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

    if current_repo_slug and not current_repo_evaluated:
        failures.append(f"{current_repo_slug}: current repo is not represented in the auditability registry")

    if generate_matrix and matrix_path:
        matrix_path.parent.mkdir(parents=True, exist_ok=True)
        matrix_path.write_text(render_matrix(registry, rows))

    if failures:
        print("[repo-auditability] validation failed")
        for f in failures:
            print(f" - {f}")
        return 1

    evaluated_count = sum(1 for r in rows if r["evaluated"])
    skipped_count = sum(1 for r in rows if not r["evaluated"])
    print(
        "[repo-auditability] auditability registry validated "
        f"({evaluated_count} evaluated, {skipped_count} registry-only)"
    )
    for r in rows:
        if not r["evaluated"]:
            print(f" - {r['repo']}: registry-only")
            continue
        print(
            f" - {r['repo']}: baseline {r['baseline_present']}/{r['baseline_total']}, "
            f"tracked {r['baseline_tracked']}/{r['baseline_total']}, "
            f"advanced {r['advanced_present']}/{r['advanced_total']}"
        )
    return 0


def render_matrix(registry, rows):
    def fmt_count(present, total, evaluated):
        return f"{present}/{total}" if evaluated else "n/a"

    lines = []
    lines.append("# AETHEL-MR-003 Repo Auditability Rollout Matrix")
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
        baseline = fmt_count(r["baseline_present"], r["baseline_total"], r["evaluated"])
        tracked = fmt_count(r["baseline_tracked"], r["baseline_total"], r["evaluated"])
        advanced = fmt_count(r["advanced_present"], r["advanced_total"], r["evaluated"])
        if not r["evaluated"]:
            readiness = "registry-only"
            notes = "not evaluated in this environment"
        elif not r["exists"] or not r["git"]:
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
        if r["evaluated"] and not r["origin_ok"]:
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
    lines.append("- `registry-only` means the repo remains in the registry but was not available as a local clone in the current execution environment.")
    lines.append("- This matrix is generated from the current checkout plus any available local sibling clones using `scripts/validate-repo-auditability.py`.")
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-matrix", action="store_true", help="Write/update the rollout matrix markdown file")
    parser.add_argument(
        "--matrix-path",
        default=str(ROOT / "docs/audits/aethel-mr-003-repo-auditability-rollout-matrix.md"),
        help="Path to write matrix markdown (used with --write-matrix)",
    )
    args = parser.parse_args()

    rc = validate(args.write_matrix, Path(args.matrix_path) if args.write_matrix else None)
    sys.exit(rc)


if __name__ == "__main__":
    main()
