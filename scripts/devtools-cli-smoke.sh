#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

NODE_BIN="${NODE_BIN:-node}"
AETH_CLI="${AETH_CLI:-${ROOT_DIR}/tools/cli/aeth/dist/index.js}"
SEAL_VERIFIER_CLI="${SEAL_VERIFIER_CLI:-${ROOT_DIR}/tools/cli/seal-verifier/dist/index.js}"

RPC_URL="${AETHELRED_SMOKE_RPC_URL:-http://127.0.0.1:26657}"
FASTAPI_URL="${AETHELRED_SMOKE_FASTAPI_URL:-http://127.0.0.1:8000}"
NEXTJS_URL="${AETHELRED_SMOKE_NEXTJS_URL:-http://127.0.0.1:3000}"
DASHBOARD_URL="${AETHELRED_SMOKE_DASHBOARD_URL:-http://127.0.0.1:3101}"
SEAL_ID="${AETHELRED_SMOKE_SEAL_ID:-seal_demo}"
TIMEOUT_SEC="${AETHELRED_SMOKE_TIMEOUT_SEC:-120}"

require_file() {
  local file="$1"
  [[ -f "$file" ]] || { echo "Missing required file: $file" >&2; exit 1; }
}

wait_for_http() {
  local url="$1"
  local label="$2"
  local deadline=$((SECONDS + TIMEOUT_SEC))
  while (( SECONDS < deadline )); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "✓ $label ready ($url)"
      return 0
    fi
    sleep 2
  done
  echo "✗ Timed out waiting for $label ($url)" >&2
  return 1
}

assert_page_contains() {
  local url="$1"
  local regex="$2"
  local label="$3"
  local tmp
  tmp="$(mktemp)"
  curl -fsS "$url" >"$tmp"
  if grep -Eq "$regex" "$tmp"; then
    echo "✓ $label content check passed"
  else
    echo "✗ $label content check failed ($url)" >&2
    echo "--- begin payload ---" >&2
    sed -n '1,120p' "$tmp" >&2
    echo "--- end payload ---" >&2
    rm -f "$tmp"
    return 1
  fi
  rm -f "$tmp"
}

run_cmd() {
  echo "+ $*"
  "$@"
}

main() {
  require_file "$AETH_CLI"
  require_file "$SEAL_VERIFIER_CLI"

  echo "== Waiting for local devtools stack =="
  wait_for_http "${RPC_URL}/health" "rpc-health"
  wait_for_http "${FASTAPI_URL}/health" "fastapi-health"
  wait_for_http "${NEXTJS_URL}/api/health" "nextjs-health"
  wait_for_http "${DASHBOARD_URL}/devtools" "dashboard-devtools"

  echo "== CLI smoke: aeth status =="
  run_cmd "$NODE_BIN" "$AETH_CLI" --rpc-url "$RPC_URL" status

  echo "== CLI smoke: aeth diagnostics doctor =="
  run_cmd "$NODE_BIN" "$AETH_CLI" --rpc-url "$RPC_URL" diagnostics doctor

  local seal_file verify_file
  seal_file="$(mktemp "${TMPDIR:-/tmp}/aethelred-smoke-seal.XXXXXX")"
  verify_file="$(mktemp "${TMPDIR:-/tmp}/aethelred-smoke-verify.XXXXXX")"
  trap "rm -f \"$seal_file\" \"$verify_file\"" EXIT

  echo "== CLI smoke: seal-verifier verify-file =="
  run_cmd curl -fsS "${RPC_URL}/aethelred/seal/v1/seals/${SEAL_ID}" -o "$seal_file"
  run_cmd "$NODE_BIN" "$SEAL_VERIFIER_CLI" verify-file "$seal_file" --json | tee "$verify_file"
  grep -q '"valid"[[:space:]]*:[[:space:]]*true' "$verify_file" || {
    echo "Seal verification did not report valid=true" >&2
    exit 1
  }
  echo "✓ seal-verifier reported valid=true"

  echo "== Dashboard HTTP checks =="
  assert_page_contains "${DASHBOARD_URL}/" "Aethelred" "dashboard-home"
  assert_page_contains "${DASHBOARD_URL}/devtools" "Developer Tools|FastAPI|Next.js" "dashboard-devtools"

  echo "All local devtools CLI smoke checks passed."
}

main "$@"
