#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${1:-.}"

compose_files=()
while IFS= read -r file; do
  compose_files+=("$file")
done < <(find "$ROOT_DIR" -type f \( -name 'docker-compose.yml' -o -name 'docker-compose.yaml' \) | sort)

if [[ ${#compose_files[@]} -eq 0 ]]; then
  echo "No docker-compose files found under $ROOT_DIR"
  exit 0
fi

fail=0

is_dev_file() {
  local f="$1"
  [[ "$f" == *"docker-compose.dev.yml" ]] && return 0
  [[ "$f" == *"docker-compose.dev.yaml" ]] && return 0
  [[ "$f" == *"/devnet/"* ]] && return 0
  [[ "$f" == *"local-testnet"* ]] && return 0
  return 1
}

check_forbidden() {
  local file="$1"
  local pattern="$2"
  local label="$3"
  if rg -n --fixed-strings "$pattern" "$file" >/dev/null; then
    echo "[FAIL] $label in non-dev compose: $file"
    rg -n --fixed-strings "$pattern" "$file" || true
    fail=1
  fi
}

for file in "${compose_files[@]}"; do
  if is_dev_file "$file"; then
    continue
  fi

  check_forbidden "$file" "AETHELRED_ALLOW_SIMULATED=true" "simulated attestation enabled"
  check_forbidden "$file" "TEE_MODE=mock" "mock TEE mode"
  check_forbidden "$file" "AETHELRED_TEE_MODE=mock" "mock TEE mode (prefixed)"
  check_forbidden "$file" "PROVER_MODE=development" "development prover mode"
  check_forbidden "$file" "GF_SECURITY_ADMIN_PASSWORD=admin" "default Grafana password"
  check_forbidden "$file" "GF_SECURITY_ADMIN_PASSWORD=\${GRAFANA_PASSWORD:-admin}" "Grafana default fallback password"
done

if [[ $fail -ne 0 ]]; then
  exit 1
fi

echo "Compose security validation passed."
