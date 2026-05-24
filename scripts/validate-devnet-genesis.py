#!/usr/bin/env python3
import argparse
import json
import math
import sys
from pathlib import Path


MIN_DEVNET_UNBONDING_SECONDS = 259_200  # 3 days
FORBIDDEN_RELEASE_MARKERS = (
    "PLACEHOLDER_",
    "deadbeef",
)


def parse_duration_seconds(value: str) -> int:
    if not value.endswith("s"):
        raise ValueError(f"unsupported duration format: {value!r}")
    return int(value[:-1])


def iter_string_values(value, path: str = "$"):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from iter_string_values(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from iter_string_values(child, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Aethelred devnet genesis parameters.")
    parser.add_argument(
        "path",
        nargs="?",
        default="tools/devnet/genesis.json",
        help="Path to the devnet genesis JSON file.",
    )
    parser.add_argument(
        "--release",
        action="store_true",
        help="Apply hosted-release checks that reject placeholder keys and measurements.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    path = Path(args.path)
    data = json.loads(path.read_text())

    consensus_params = data["consensus"]["params"]
    staking = data["staking"]
    validators = data.get("validators", [])
    validator_count = len(validators)

    errors: list[str] = []

    consensus_unbonding = parse_duration_seconds(consensus_params["unbondingPeriod"])
    staking_unbonding = parse_duration_seconds(staking["unbondingTime"])
    if consensus_unbonding < MIN_DEVNET_UNBONDING_SECONDS:
        errors.append(
            f"consensus.params.unbondingPeriod={consensus_params['unbondingPeriod']} is below {MIN_DEVNET_UNBONDING_SECONDS}s"
        )
    if staking_unbonding < MIN_DEVNET_UNBONDING_SECONDS:
        errors.append(
            f"staking.unbondingTime={staking['unbondingTime']} is below {MIN_DEVNET_UNBONDING_SECONDS}s"
        )

    min_attestations = int(consensus_params["minAttestationsForSeal"])
    required = max(2, math.ceil(validator_count * 0.67)) if validator_count > 0 else 2
    if min_attestations < required:
        errors.append(
            f"consensus.params.minAttestationsForSeal={min_attestations} is below required floor {required} for {validator_count} validators"
        )

    default_min_attestations = int(data["computeModule"]["slaConfig"]["defaultMinAttestations"])
    if default_min_attestations < required:
        errors.append(
            f"computeModule.slaConfig.defaultMinAttestations={default_min_attestations} is below required floor {required}"
        )

    if args.release:
        for value_path, value in iter_string_values(data):
            lower_value = value.lower()
            for marker in FORBIDDEN_RELEASE_MARKERS:
                if marker.lower() in lower_value:
                    errors.append(f"{value_path} contains release-blocking placeholder marker {marker!r}")
                    break

    if errors:
        print("Devnet genesis validation failed:")
        for err in errors:
            print(f" - {err}")
        return 1

    print(
        "Devnet genesis validation passed "
        f"(validators={validator_count}, minAttestationsForSeal={min_attestations}, unbonding={consensus_params['unbondingPeriod']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
