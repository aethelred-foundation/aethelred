#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART_DIR="${ROOT_DIR}/integrations/deploy/helm/aethelred-validator"
BASE_VALUES="${CHART_DIR}/values.yaml"
PRODUCTION_VALUES="${CHART_DIR}/values/production.yaml"
RENDERED="${TMPDIR:-/tmp}/aethelred-validator-rendered.yaml"

if ! command -v helm >/dev/null 2>&1; then
  echo "Helm is required to validate the validator chart." >&2
  exit 1
fi

helm lint "${CHART_DIR}" -f "${BASE_VALUES}" -f "${PRODUCTION_VALUES}"
helm template aethelred-validator "${CHART_DIR}" \
  --namespace aethelred \
  -f "${BASE_VALUES}" \
  -f "${PRODUCTION_VALUES}" > "${RENDERED}"

fail=0

reject_pattern() {
  local pattern="$1"
  local label="$2"
  if grep -Eq "${pattern}" "${RENDERED}"; then
    echo "[FAIL] ${label}"
    grep -En "${pattern}" "${RENDERED}" || true
    fail=1
  fi
}

require_text() {
  local text="$1"
  local label="$2"
  if ! grep -Fq "${text}" "${RENDERED}"; then
    echo "[FAIL] missing ${label}: ${text}"
    fail=1
  fi
}

reject_pattern 'type: LoadBalancer' "validator RPC must not render as a public LoadBalancer"
reject_pattern ':(latest|stable)"' "image tags must not use mutable latest/stable tags"
reject_pattern 'privileged: true' "privileged containers require an explicit hardware exception overlay"
reject_pattern 'allowPrivilegeEscalation: true' "privilege escalation must remain disabled"

require_text 'allowPrivilegeEscalation: false' "container privilege escalation control"
require_text 'readOnlyRootFilesystem: true' "read-only container root filesystem"
require_text 'seccompProfile:' "seccomp profile"
require_text 'drop:' "Linux capability drop list"
require_text 'cpu: "32"' "production validator CPU request"
require_text 'memory: "128Gi"' "production validator memory request"
require_text 'storage: 2Ti' "production validator PVC size"

if [[ "${fail}" -ne 0 ]]; then
  exit 1
fi

echo "Validator Helm chart validation passed."
