#!/usr/bin/env python3
import json
import math
import sys
from pathlib import Path


MIN_DEVNET_UNBONDING_SECONDS = 259_200  # 3 days


def parse_duration_seconds(value: str) -> int:
    if not value.endswith("s"):
        raise ValueError(f"unsupported duration format: {value!r}")
    return int(value[:-1])


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("tools/devnet/genesis.json")
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

