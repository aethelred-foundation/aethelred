#!/usr/bin/env python3
"""Validate SDK release tags/inputs against version-matrix.json."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
TAG_RE = re.compile(r"^sdk-(python|typescript|rust|go)-v(.+)$")
VALID_TARGETS = ("python", "typescript", "rust", "go")


def load_matrix(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Version matrix not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def parse_tag(tag: str) -> tuple[str, str]:
    match = TAG_RE.match(tag)
    if not match:
        raise ValueError(
            "Invalid tag format. Expected sdk-<python|typescript|rust|go>-v<semver>"
        )
    target, version = match.group(1), match.group(2)
    return target, version


def bool_str(value: bool) -> str:
    return "true" if value else "false"


def write_outputs(path: Path, outputs: dict[str, str]) -> None:
    lines = [f"{k}={v}" for k, v in outputs.items()]
    with path.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines))
        f.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", default="version-matrix.json")
    parser.add_argument("--tag", default="")
    parser.add_argument("--target", default="")
    parser.add_argument("--version", default="")
    parser.add_argument("--publish-requested", default="false")
    parser.add_argument("--enforce-publishability", action="store_true")
    parser.add_argument("--github-output", default="")
    args = parser.parse_args()

    matrix = load_matrix(Path(args.matrix))
    packages = matrix.get("packages", {})

    if args.tag and (args.target or args.version):
        print("Use either --tag or --target/--version, not both.", file=sys.stderr)
        return 1

    if args.tag:
        target, version = parse_tag(args.tag)
    else:
        if not args.target or not args.version:
            print("When --tag is absent, --target and --version are required.", file=sys.stderr)
            return 1
        target, version = args.target, args.version
        if target not in VALID_TARGETS:
            print(
                f"Invalid target '{target}'. Expected one of: {', '.join(VALID_TARGETS)}",
                file=sys.stderr,
            )
            return 1

    if not SEMVER_RE.match(version):
        print(f"Invalid semver version: {version}", file=sys.stderr)
        return 1

    if target not in packages:
        print(f"Target '{target}' missing in version matrix packages.", file=sys.stderr)
        return 1

    expected_version = packages[target].get("version", "")
    if version != expected_version:
        print(
            f"Version mismatch for {target}: tag/input={version}, matrix={expected_version}",
            file=sys.stderr,
        )
        return 1

    publish_requested = args.publish_requested.lower() == "true"
    publish_enabled = bool(packages[target].get("published", False))

    if publish_requested and args.enforce_publishability and not publish_enabled:
        print(
            f"Publishing blocked for target '{target}'. "
            "Set packages.<target>.published=true in version-matrix.json first.",
            file=sys.stderr,
        )
        return 1

    outputs = {
        "target": target,
        "version": version,
        "publish_requested": bool_str(publish_requested),
        "publish_enabled": bool_str(publish_enabled),
        "publish_python": bool_str(target == "python"),
        "publish_typescript": bool_str(target == "typescript"),
        "publish_rust": bool_str(target == "rust"),
        "publish_go": bool_str(target == "go"),
    }

    if args.github_output:
        write_outputs(Path(args.github_output), outputs)
    else:
        print(json.dumps(outputs, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
