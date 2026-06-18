#!/usr/bin/env python3
"""Validate local devnet topology, endpoint, and onboarding doc consistency."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "integrations/deploy/docker/docker-compose.yml"

EXPECTED_PORTS = {
    "validator-alice": ["8545:8545", "8546:8546", "8547:8547"],
    "validator-bob": ["8555:8545"],
    "compute-charlie": ["8565:8545"],
    "bridge-relayer": ["9104:9100"],
    "prometheus": ["9090:9090"],
    "grafana": ["3000:3000"],
    "faucet": ["8080:8080"],
    "explorer": ["4000:4000"],
}

REQUIRED_TEXT = {
    "scripts/devnet-control.sh": [
        "http://localhost:8545",
        "ws://localhost:8546",
        "http://localhost:8547/graphql",
        "http://localhost:8080",
        "http://localhost:4000",
        "http://localhost:9090",
        "http://localhost:3000",
    ],
    "integrations/deploy/scripts/setup-devnet.sh": [
        'DEPLOY_DIR="${DEPLOY_ROOT}"',
        'local contracts_dir="${REPO_ROOT}/contracts"',
        "http://localhost:8080",
        "http://localhost:4000",
        "http://localhost:9090",
        "http://localhost:3000",
    ],
    "integrations/deploy/scripts/healthcheck.sh": [
        "http://localhost:8545/health",
        "http://localhost:8555/health",
        "http://localhost:8565/health",
        "http://localhost:9104/health",
        "http://localhost:8080/health",
        "http://localhost:4000/health",
        "http://localhost:9090/-/healthy",
        "http://localhost:3000/api/health",
    ],
    "docs/devnet/README.md": [
        "http://localhost:8080",
        "http://localhost:4000",
        "http://localhost:9090",
        "http://localhost:3000",
        "http://localhost:5173",
    ],
    "docs/demo/README.md": [
        "cd docs/demo/dashboard",
        "http://localhost:5173",
        "http://localhost:4000",
        "http://localhost:8080",
    ],
    "docs/guides/demo-quickstart.md": [
        "cd docs/demo/dashboard",
        "http://localhost:5173",
        "http://localhost:4000",
        "http://localhost:8080",
    ],
    "docs/demo/scenarios/developer-onboard.json": [
        "http://localhost:4000",
        "http://localhost:8080",
        "http://localhost:8545",
    ],
}

FORBIDDEN_TEXT = {
    "http://localhost:8081": "stale faucet endpoint",
    "http://localhost:9091": "stale Prometheus endpoint",
    "http://localhost:3001": "stale Grafana endpoint",
    "cd demo/dashboard": "stale demo dashboard path",
    "Open http://localhost:3000": "demo dashboard must not use the Grafana port",
    "Dashboard starting at http://localhost:3000": "demo dashboard must not use the Grafana port",
    "DEPLOY_DIR=\"${PROJECT_ROOT}/deploy\"": "stale nested deployment root",
}


def service_block(compose_text: str, service: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(service)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        compose_text,
    )
    return match.group(1) if match else ""


def main() -> int:
    errors: list[str] = []
    compose_text = COMPOSE.read_text()

    if re.search(r"(?m)^version\s*:", compose_text):
        errors.append("integrations/deploy/docker/docker-compose.yml must not use obsolete top-level version")

    for service, expected_ports in EXPECTED_PORTS.items():
        block = service_block(compose_text, service)
        if not block:
            errors.append(f"compose service missing: {service}")
            continue
        for port in expected_ports:
            if f'"{port}"' not in block and f"'{port}'" not in block and f"- {port}" not in block:
                errors.append(f"compose service {service} missing port mapping {port}")

    for rel_path, required_values in REQUIRED_TEXT.items():
        path = ROOT / rel_path
        if not path.exists():
            errors.append(f"required devnet topology file missing: {rel_path}")
            continue
        text = path.read_text()
        for required in required_values:
            if required not in text:
                errors.append(f"{rel_path} missing expected value: {required}")

    checked_paths = [ROOT / rel_path for rel_path in REQUIRED_TEXT]
    checked_paths.append(ROOT / "docs/SDK_GUIDE.md")
    checked_paths.append(ROOT / "docs/demo/run-demo.sh")

    for path in checked_paths:
        if not path.exists():
            continue
        text = path.read_text()
        for forbidden, label in FORBIDDEN_TEXT.items():
            if forbidden in text:
                errors.append(f"{path.relative_to(ROOT)} contains {label}: {forbidden}")

    if errors:
        print("Devnet topology validation failed:")
        for error in errors:
            print(f" - {error}")
        return 1

    print("Devnet topology validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
