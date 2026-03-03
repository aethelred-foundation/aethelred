#!/usr/bin/env python3
"""Validate SDK release provenance controls and generate a status matrix."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
import sys
import tomllib


SDK_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = SDK_ROOT.parent

REGISTRY_PATH = SDK_ROOT / "docs/security/release-provenance-registry.json"
SDK_MATRIX_PATH = SDK_ROOT / "version-matrix.json"
ROOT_MATRIX_PATH = WORKSPACE_ROOT / "version-matrix.json"
STATUS_MD_PATH = SDK_ROOT / "docs/security/release-provenance-status.md"
STATUS_JSON_PATH = SDK_ROOT / "docs/security/release-provenance-status.json"

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+].*)?$")
GO_CONST_VERSION_RE = re.compile(r"\bVersion\s*=\s*\"([^\"]+)\"")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def read_toml_version(path: Path, dotted: tuple[str, ...]) -> str:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    cur = data
    for key in dotted:
        cur = cur[key]
    return str(cur)


def read_pkg_version(path: Path) -> str:
    return str(json.loads(path.read_text(encoding="utf-8"))["version"])


def read_go_version(path: Path) -> str:
    m = GO_CONST_VERSION_RE.search(path.read_text(encoding="utf-8"))
    if not m:
        raise ValueError(f"missing Go Version const in {path}")
    return m.group(1)


def manifest_version_for(pkg_id: str, manifest_path: Path) -> str:
    if pkg_id == "python":
        return read_toml_version(manifest_path, ("project", "version"))
    if pkg_id == "typescript":
        return read_pkg_version(manifest_path)
    if pkg_id == "rust":
        return read_toml_version(manifest_path, ("package", "version"))
    if pkg_id == "go":
        # version source is in go/aethelred.go, not go.mod
        return read_go_version(SDK_ROOT / "go" / "aethelred.go")
    raise ValueError(f"unsupported sdk package id {pkg_id}")


def workflow_contains_controls(path: Path) -> dict[str, bool]:
    content = path.read_text(encoding="utf-8") if path.exists() else ""
    return {
        "has_sha256sums": "SHA256SUMS" in content,
        "uploads_artifact": "actions/upload-artifact@" in content,
        "copies_version_matrix": "version-matrix.sdk.json" in content or "version-matrix.json" in content,
        "mentions_attestation": "attest" in content.lower() or "provenance" in content.lower(),
        "builds_python": "python -m build" in content,
        "builds_typescript": "npm pack" in content,
        "builds_rust": "cargo package" in content,
        "handles_go": (" go " in content.lower()) or ("go/" in content.lower()),
    }


def build_status(write_status: bool) -> int:
    registry = load_json(REGISTRY_PATH)
    sdk_matrix = load_json(SDK_MATRIX_PATH)
    root_matrix = load_json(ROOT_MATRIX_PATH) if ROOT_MATRIX_PATH.exists() else None
    errors: list[str] = []

    if root_matrix is not None and sdk_matrix != root_matrix:
        errors.append("sdk/version-matrix.json does not match root version-matrix.json")

    rows: list[dict] = []

    for rel in registry["required_repo_docs"]:
        if not (SDK_ROOT / rel).exists():
            errors.append(f"missing required repo doc: {rel}")
    for rel in registry["required_workflows"]:
        if not (SDK_ROOT / rel).exists():
            errors.append(f"missing required workflow: {rel}")

    readme_text = (SDK_ROOT / "README.md").read_text(encoding="utf-8").lower()
    provenance_doc = (SDK_ROOT / "docs/security/release-provenance.md").read_text(encoding="utf-8").lower()
    if "source-first" not in readme_text:
        errors.append("sdk/README.md must disclose source-first install status")
    if "checksums" not in provenance_doc or "provenance" not in provenance_doc:
        errors.append("docs/security/release-provenance.md missing checksum/provenance requirements")

    workflow_path = SDK_ROOT / ".github/workflows/sdk-release-provenance-local.yml"
    wf_controls = workflow_contains_controls(workflow_path)
    if not wf_controls["has_sha256sums"]:
        errors.append("sdk-release-provenance-local.yml missing SHA256SUMS generation")
    if not wf_controls["uploads_artifact"]:
        errors.append("sdk-release-provenance-local.yml missing artifact upload")
    if not wf_controls["copies_version_matrix"]:
        errors.append("sdk-release-provenance-local.yml missing version matrix capture")

    for pkg in registry["sdk_packages"]:
        pkg_id = pkg["id"]
        matrix_key = pkg["matrix_key"]
        manifest_rel = pkg["manifest_path"]
        manifest_path = SDK_ROOT / manifest_rel
        matrix_pkg = sdk_matrix["packages"][matrix_key]

        row = {
            "id": pkg_id,
            "display_name": pkg["display_name"],
            "registry": pkg["registry"],
            "manifest_path": manifest_rel,
            "manifest_exists": manifest_path.exists(),
            "matrix_version": matrix_pkg.get("version"),
            "manifest_version": None,
            "version_match": False,
            "published": bool(matrix_pkg.get("published", False)),
            "expected_artifact_extensions": pkg.get("expected_artifact_extensions", []),
            "build_command_doc": pkg.get("build_command_doc", ""),
        }

        if not row["manifest_exists"]:
            errors.append(f"{pkg_id}: missing manifest {manifest_rel}")
            rows.append(row)
            continue

        try:
            row["manifest_version"] = manifest_version_for(pkg_id, manifest_path)
        except Exception as exc:
            errors.append(f"{pkg_id}: failed to read manifest version: {exc}")
            rows.append(row)
            continue

        if not SEMVER_RE.match(str(row["matrix_version"])):
            errors.append(f"{pkg_id}: matrix version is not semver ({row['matrix_version']})")
        if not SEMVER_RE.match(str(row["manifest_version"])):
            errors.append(f"{pkg_id}: manifest version is not semver ({row['manifest_version']})")

        row["version_match"] = str(row["matrix_version"]) == str(row["manifest_version"])
        if not row["version_match"]:
            errors.append(
                f"{pkg_id}: matrix version {row['matrix_version']} != manifest version {row['manifest_version']}"
            )

        rows.append(row)

    if write_status:
        STATUS_MD_PATH.write_text(render_status(registry, rows, wf_controls, errors), encoding="utf-8")
        STATUS_JSON_PATH.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "date": registry.get("effective_date", "unknown"),
                    "validation_ok": not bool(errors),
                    "errors": errors,
                    "workflow_controls": wf_controls,
                    "packages": rows,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    if errors:
        print("[sdk-release-provenance] validation failed")
        for e in errors:
            print(f" - {e}")
        return 1

    print("[sdk-release-provenance] registry/workflows/docs/version matrix validated")
    for row in rows:
        print(
            f" - {row['id']}: version={row['manifest_version']} "
            f"published={row['published']} version_match={row['version_match']}"
        )
    return 0


def render_status(registry: dict, rows: list[dict], wf_controls: dict[str, bool], errors: list[str]) -> str:
    lines: list[str] = []
    lines.append("# SDK Release Provenance Status")
    lines.append("")
    lines.append(f"Date: {registry.get('effective_date', 'unknown')}")
    lines.append("Purpose: Machine-generated status for `AETH-MR-005` release provenance controls in the SDK monorepo.")
    lines.append("")
    lines.append("## Repo-Level Controls")
    for rel in registry["required_repo_docs"]:
        lines.append(f"- {'OK' if (SDK_ROOT / rel).exists() else 'MISSING'} `{rel}`")
    for rel in registry["required_workflows"]:
        lines.append(f"- {'OK' if (SDK_ROOT / rel).exists() else 'MISSING'} `{rel}`")
    lines.append("")
    lines.append("## Provenance Workflow Coverage (`sdk-release-provenance-local.yml`)")
    for k, v in wf_controls.items():
        lines.append(f"- {'OK' if v else 'MISSING'} `{k}`")
    lines.append("")
    lines.append("## SDK Package Provenance Readiness")
    lines.append("")
    lines.append("| SDK | Registry | Manifest | Version (Matrix) | Version (Manifest) | Match | Published Flag |")
    lines.append("|---|---|---|---:|---:|---|---|")
    for row in rows:
        lines.append(
            f"| {row['display_name']} | `{row['registry']}` | `{row['manifest_path']}` | "
            f"`{row['matrix_version']}` | `{row['manifest_version'] or 'n/a'}` | "
            f"{'OK' if row['version_match'] else 'FAIL'} | "
            f"{'published' if row['published'] else 'pending'} |"
        )
    lines.append("")
    lines.append("## Release Bundle Requirements (Target)")
    for rel in registry["required_release_bundle_files"]:
        lines.append(f"- `{rel}`")
    lines.append("")
    if errors:
        lines.append("## Validation Errors")
        for e in errors:
            lines.append(f"- {e}")
        lines.append("")
    else:
        lines.append("## Validation Result")
        lines.append("- All machine-checkable release provenance controls passed.")
        lines.append("")
    lines.append("Generated by `sdk/scripts/validate_release_provenance.py`.")
    if ROOT_MATRIX_PATH.exists():
        lines.append("- Root version matrix comparison was performed (`../version-matrix.json`).")
    else:
        lines.append("- Root version matrix comparison was skipped (standalone SDK repo mode).")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-status", action="store_true", help="Write the generated status markdown file")
    args = parser.parse_args()
    return build_status(write_status=args.write_status)


if __name__ == "__main__":
    raise SystemExit(main())
