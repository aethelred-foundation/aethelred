#!/usr/bin/env python3
"""Validate SDK/API versions against the version matrix."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]
ROOT_MATRIX_PATH = ROOT / "version-matrix.json"
SDK_MATRIX_PATH = ROOT / "sdk" / "version-matrix.json"

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
GO_VERSION_RE = re.compile(r"\bVersion\s*=\s*\"([^\"]+)\"")
GO_MODULE_RE = re.compile(r"^\s*module\s+(\S+)\s*$", re.MULTILINE)
README_SDK_GO_ROW_RE = re.compile(
    r"^\|\s*\[`sdk-go`\]\(\./go\)\s*\|[^|]*\|\s*([^|]+)\|", re.MULTILINE
)
README_CLI_ROW_RE = re.compile(
    r"^\|\s*\[`aethel`\]\(\./cli/aethel\)\s*\|\s*([^|]+)\|", re.MULTILINE
)


def read_openapi_version(path: Path) -> str:
    in_info = False
    info_indent = 0
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        if stripped == "info:":
            in_info = True
            info_indent = indent
            continue

        if in_info and indent <= info_indent:
            in_info = False

        if in_info and stripped.startswith("version:"):
            return stripped.split(":", 1)[1].strip().strip('"\'')

    raise ValueError(f"Could not find info.version in {path}")


def read_toml_version(path: Path) -> str:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return data["package"]["version"]


def read_pyproject_version(path: Path) -> str:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return data["project"]["version"]


def read_package_json_version(path: Path) -> str:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["version"]


def read_go_const_version(path: Path) -> str:
    match = GO_VERSION_RE.search(path.read_text(encoding="utf-8"))
    if not match:
        raise ValueError(f"Could not find Go Version constant in {path}")
    return match.group(1)


def read_go_module(path: Path) -> str:
    match = GO_MODULE_RE.search(path.read_text(encoding="utf-8"))
    if not match:
        raise ValueError(f"Could not find module directive in {path}")
    return match.group(1)


def read_sdk_readme_go_version(path: Path) -> str:
    content = path.read_text(encoding="utf-8")
    match = README_SDK_GO_ROW_RE.search(content)
    if not match:
        raise ValueError(f"Could not find sdk-go version row in {path}")
    return match.group(1).strip()


def read_sdk_readme_cli_version(path: Path) -> str:
    content = path.read_text(encoding="utf-8")
    match = README_CLI_ROW_RE.search(content)
    if not match:
        raise ValueError(f"Could not find CLI version row in {path}")
    return match.group(1).strip()


def require_semver(label: str, value: str, errors: list[str]) -> None:
    if not SEMVER_RE.match(value):
        errors.append(f"{label}: invalid semver '{value}'")


def load_matrix() -> tuple[Path, dict]:
    if ROOT_MATRIX_PATH.exists():
        matrix = json.loads(ROOT_MATRIX_PATH.read_text(encoding="utf-8"))
        if SDK_MATRIX_PATH.exists():
            sdk_matrix = json.loads(SDK_MATRIX_PATH.read_text(encoding="utf-8"))
            if matrix != sdk_matrix:
                raise ValueError(
                    f"Version matrix mismatch between {ROOT_MATRIX_PATH} and {SDK_MATRIX_PATH}"
                )
        return ROOT_MATRIX_PATH, matrix

    if SDK_MATRIX_PATH.exists():
        return SDK_MATRIX_PATH, json.loads(SDK_MATRIX_PATH.read_text(encoding="utf-8"))

    raise FileNotFoundError(
        f"Missing version matrix. Expected {ROOT_MATRIX_PATH} or {SDK_MATRIX_PATH}"
    )


def main() -> int:
    matrix_path, matrix = load_matrix()
    pkg = matrix["packages"]

    checks = {
        "typescript": (
            pkg["typescript"]["version"],
            read_package_json_version(ROOT / pkg["typescript"]["path"]),
        ),
        "python": (
            pkg["python"]["version"],
            read_pyproject_version(ROOT / pkg["python"]["path"]),
        ),
        "rust": (
            pkg["rust"]["version"],
            read_toml_version(ROOT / pkg["rust"]["path"]),
        ),
        "go": (
            pkg["go"]["version"],
            read_go_const_version(ROOT / pkg["go"]["path"]),
        ),
        "cli": (
            pkg["cli"]["version"],
            read_toml_version(ROOT / pkg["cli"]["path"]),
        ),
        "native_rust": (
            pkg["native_rust"]["version"],
            read_toml_version(ROOT / pkg["native_rust"]["path"]),
        ),
        "native_python": (
            pkg["native_python"]["version"],
            read_toml_version(ROOT / pkg["native_python"]["path"]),
        ),
        "openapi": (
            matrix["api"]["openapi_version"],
            read_openapi_version(ROOT / "sdk" / "spec" / "openapi.yaml"),
        ),
        "sdk_readme_go": (
            pkg["go"]["version"],
            read_sdk_readme_go_version(ROOT / "sdk" / "README.md"),
        ),
        "sdk_readme_cli": (
            pkg["cli"]["version"],
            read_sdk_readme_cli_version(ROOT / "sdk" / "README.md"),
        ),
    }

    errors: list[str] = []

    go_module_expected = pkg["go"].get("module", "")
    go_module_actual = read_go_module(ROOT / "sdk" / "go" / "go.mod")
    if go_module_expected and go_module_expected != go_module_actual:
        errors.append(
            f"go_module: expected {go_module_expected}, found {go_module_actual}"
        )

    for package_name, package_data in pkg.items():
        published = package_data.get("published")
        if published is not None and not isinstance(published, bool):
            errors.append(f"{package_name}.published must be boolean when present")

    for name, (expected, actual) in checks.items():
        require_semver(name, expected, errors)
        require_semver(name, actual, errors)
        if expected != actual:
            errors.append(f"{name}: expected {expected}, found {actual}")

    print("SDK/API version checks:")
    print(f"  - matrix_path   {matrix_path}")
    for name, (expected, actual) in checks.items():
        status = "OK" if expected == actual else "MISMATCH"
        print(f"  - {name:<13} expected={expected:<10} actual={actual:<10} [{status}]")
    print(
        f"  - go_module    expected={go_module_expected:<28} actual={go_module_actual:<28} "
        f"[{'OK' if go_module_expected == go_module_actual else 'MISMATCH'}]"
    )

    if errors:
        print("\nVersion check failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("\nVersion check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
