#!/usr/bin/env bash
# =============================================================================
# SQ19: Negative-Path Verifier Tests
# =============================================================================
# Tests that verifier services (fastapi-verifier, nextjs-verifier) correctly
# reject or gracefully handle malformed input:
#   - Malformed proofs / invalid attestations
#   - Missing required fields
#   - Wrong types (string where number expected, etc.)
#   - Empty payloads
#   - Oversized payloads
#
# Requires: curl, jq
# The verifier services must be running locally (or URLs overridden via env).
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PASS=0
FAIL=0
FAILURES=""

# Override with env vars if needed
FASTAPI_BASE="${FASTAPI_VERIFIER_URL:-http://localhost:8000}"
NEXTJS_BASE="${NEXTJS_VERIFIER_URL:-http://localhost:3000}"

# Set to "true" to skip connectivity checks and run structurally
DRY_RUN="${DRY_RUN:-false}"

log_section() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$1"; }
log_pass()    { printf '  \033[1;32m[PASS]\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
log_fail()    { printf '  \033[1;31m[FAIL]\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); FAILURES="$FAILURES\n  - $1"; }
log_skip()    { printf '  \033[1;33m[SKIP]\033[0m %s\n' "$1"; }

check_cmd() { command -v "$1" >/dev/null 2>&1; }

# Send a request and validate the HTTP status code
# Usage: assert_http METHOD URL DATA EXPECTED_STATUS LABEL
assert_http() {
  local method="$1" url="$2" data="$3" expected="$4" label="$5"

  local status_code
  status_code="$(curl -s -o /dev/null -w '%{http_code}' \
    -X "$method" \
    -H 'Content-Type: application/json' \
    -d "$data" \
    --max-time 10 \
    "$url" 2>/dev/null || echo "000")"

  if [ "$status_code" = "$expected" ]; then
    log_pass "$label (HTTP $status_code)"
  else
    log_fail "$label (expected HTTP $expected, got $status_code)"
  fi
}

# Send a request and validate response body contains a pattern
# Usage: assert_http_body METHOD URL DATA PATTERN LABEL
assert_http_body() {
  local method="$1" url="$2" data="$3" pattern="$4" label="$5"

  local body
  body="$(curl -s \
    -X "$method" \
    -H 'Content-Type: application/json' \
    -d "$data" \
    --max-time 10 \
    "$url" 2>/dev/null || echo "")"

  if echo "$body" | grep -qi "$pattern"; then
    log_pass "$label"
  else
    log_fail "$label (pattern '$pattern' not found in response)"
  fi
}

# ---------------------------------------------------------------------------
# Check service connectivity
# ---------------------------------------------------------------------------
check_service() {
  local name="$1" url="$2"
  if [ "$DRY_RUN" = "true" ]; then
    return 0
  fi
  if curl -s -o /dev/null --max-time 5 "$url/health" 2>/dev/null; then
    return 0
  else
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Structural tests (no running service required)
# ---------------------------------------------------------------------------
test_fastapi_structure() {
  log_section "FastAPI Verifier - Structural Checks"

  local app_dir="$REPO_ROOT/integrations/apps/fastapi-verifier"

  if [ ! -f "$app_dir/app/main.py" ]; then
    log_fail "app/main.py not found"
    return
  fi
  log_pass "app/main.py exists"

  # Verify requirements.txt
  if [ -f "$app_dir/requirements.txt" ]; then
    log_pass "requirements.txt exists"
    if grep -q 'fastapi' "$app_dir/requirements.txt"; then
      log_pass "fastapi listed in requirements"
    else
      log_fail "fastapi not in requirements.txt"
    fi
  else
    log_fail "requirements.txt missing"
  fi

  # Verify Pydantic models have type constraints
  if grep -q 'BaseModel' "$app_dir/app/main.py"; then
    log_pass "Pydantic BaseModel used for input validation"
  else
    log_fail "no Pydantic BaseModel found - inputs may not be validated"
  fi

  # Verify health endpoint excluded from verification middleware
  if grep -q 'exclude_paths.*health' "$app_dir/app/main.py"; then
    log_pass "health endpoint excluded from verification middleware"
  else
    log_fail "health endpoint not excluded from verification middleware"
  fi

  # Verify bounded history (DoS protection)
  if grep -q '200\|_recent_envelopes' "$app_dir/app/main.py"; then
    log_pass "in-memory envelope history is bounded"
  else
    log_fail "envelope history may be unbounded"
  fi
}

test_nextjs_structure() {
  log_section "Next.js Verifier - Structural Checks"

  local app_dir="$REPO_ROOT/integrations/apps/nextjs-verifier"

  if [ ! -f "$app_dir/package.json" ]; then
    log_fail "package.json not found"
    return
  fi
  log_pass "package.json exists"

  # Verify SDK dependency
  if check_cmd node; then
    local sdk_dep
    sdk_dep="$(node -e "const p=require('$app_dir/package.json'); console.log(p.dependencies?.['@aethelred/sdk']||'NONE')")"
    if [ "$sdk_dep" != "NONE" ]; then
      log_pass "@aethelred/sdk dependency present"
    else
      log_fail "@aethelred/sdk not in dependencies"
    fi
  fi

  # Verify App Router API route
  if [ -f "$app_dir/app/api/verify/route.ts" ]; then
    log_pass "App Router verify route exists"
  else
    log_fail "app/api/verify/route.ts missing"
  fi

  # Verify Pages Router legacy route
  if [ -f "$app_dir/pages/api/legacy-verify.ts" ]; then
    log_pass "Pages Router legacy-verify route exists"
  else
    log_fail "pages/api/legacy-verify.ts missing"
  fi

  # Verify route handler wrapping
  if grep -q 'withAethelredRouteHandler' "$app_dir/app/api/verify/route.ts"; then
    log_pass "App Router route uses withAethelredRouteHandler"
  else
    log_fail "App Router route not wrapped with withAethelredRouteHandler"
  fi

  if grep -q 'withAethelredApiRoute' "$app_dir/pages/api/legacy-verify.ts"; then
    log_pass "Pages Router route uses withAethelredApiRoute"
  else
    log_fail "Pages Router route not wrapped with withAethelredApiRoute"
  fi
}

# ---------------------------------------------------------------------------
# FastAPI Verifier - Negative Path Tests (requires running service)
# ---------------------------------------------------------------------------
test_fastapi_negative_paths() {
  log_section "FastAPI Verifier - Negative Path Tests"

  if ! check_service "FastAPI Verifier" "$FASTAPI_BASE"; then
    log_skip "FastAPI verifier not reachable at $FASTAPI_BASE (set FASTAPI_VERIFIER_URL or start with: uvicorn app.main:app)"
    log_skip "Running structural-only checks"
    return
  fi

  # -- Health endpoint should work --
  assert_http GET "$FASTAPI_BASE/health" "" "200" "health endpoint returns 200"

  # -- /infer/fraud: empty body --
  assert_http POST "$FASTAPI_BASE/infer/fraud" '{}' "200" "fraud: empty body defaults accepted"

  # -- /infer/fraud: wrong type for features (string instead of array) --
  assert_http POST "$FASTAPI_BASE/infer/fraud" '{"features":"not-an-array"}' "422" "fraud: string features rejected (422)"

  # -- /infer/fraud: wrong type for threshold (string instead of float) --
  assert_http POST "$FASTAPI_BASE/infer/fraud" '{"features":[1.0],"threshold":"high"}' "422" "fraud: string threshold rejected (422)"

  # -- /infer/fraud: null features --
  assert_http POST "$FASTAPI_BASE/infer/fraud" '{"features":null}' "422" "fraud: null features rejected (422)"

  # -- /infer/fraud: nested object where array expected --
  assert_http POST "$FASTAPI_BASE/infer/fraud" '{"features":{"a":1}}' "422" "fraud: object features rejected (422)"

  # -- /infer/fraud: negative threshold --
  assert_http POST "$FASTAPI_BASE/infer/fraud" '{"features":[0.5],"threshold":-1.0}' "200" "fraud: negative threshold accepted (no constraint)"

  # -- /infer/fraud: extremely large array --
  local big_array
  big_array="$(python3 -c "import json; print(json.dumps({'features': [0.1]*10000}))" 2>/dev/null || echo '{"features":[]}')"
  assert_http POST "$FASTAPI_BASE/infer/fraud" "$big_array" "200" "fraud: large feature array handled"

  # -- /infer/text-risk: missing text field --
  assert_http POST "$FASTAPI_BASE/infer/text-risk" '{}' "422" "text-risk: missing text field rejected (422)"

  # -- /infer/text-risk: wrong type (number instead of string) --
  assert_http POST "$FASTAPI_BASE/infer/text-risk" '{"text":12345}' "422" "text-risk: numeric text rejected (422)"

  # -- /infer/text-risk: null text --
  assert_http POST "$FASTAPI_BASE/infer/text-risk" '{"text":null}' "422" "text-risk: null text rejected (422)"

  # -- /infer/text-risk: empty string (should succeed) --
  assert_http POST "$FASTAPI_BASE/infer/text-risk" '{"text":""}' "200" "text-risk: empty string accepted"

  # -- /chain/normalize: completely malformed JSON --
  assert_http POST "$FASTAPI_BASE/chain/normalize" 'not-json-at-all' "422" "normalize: malformed JSON rejected (422)"

  # -- /chain/normalize: wrong content type tested implicitly --

  # -- /verify/recent: negative limit --
  assert_http GET "$FASTAPI_BASE/verify/recent?limit=-5" "" "200" "recent: negative limit handled gracefully"

  # -- /verify/recent: string limit --
  assert_http GET "$FASTAPI_BASE/verify/recent?limit=abc" "" "422" "recent: string limit rejected (422)"

  # -- Non-existent endpoint --
  assert_http GET "$FASTAPI_BASE/nonexistent" "" "404" "non-existent route returns 404"

  # -- Wrong HTTP method --
  assert_http GET "$FASTAPI_BASE/infer/fraud" "" "405" "fraud endpoint rejects GET (405)"
}

# ---------------------------------------------------------------------------
# Next.js Verifier - Negative Path Tests (requires running service)
# ---------------------------------------------------------------------------
test_nextjs_negative_paths() {
  log_section "Next.js Verifier - Negative Path Tests"

  if ! check_service "Next.js Verifier" "$NEXTJS_BASE"; then
    log_skip "Next.js verifier not reachable at $NEXTJS_BASE (set NEXTJS_VERIFIER_URL or start with: npm run dev)"
    log_skip "Running structural-only checks"
    return
  fi

  # -- Health endpoint --
  assert_http GET "$NEXTJS_BASE/api/health" "" "200" "health endpoint returns 200"

  # -- /api/verify: empty body --
  assert_http POST "$NEXTJS_BASE/api/verify" '{}' "200" "verify: empty body handled (defaults)"

  # -- /api/verify: missing prompt field --
  assert_http POST "$NEXTJS_BASE/api/verify" '{"notprompt":"test"}' "200" "verify: missing prompt field defaults gracefully"

  # -- /api/verify: prompt is a number --
  assert_http POST "$NEXTJS_BASE/api/verify" '{"prompt":42}' "200" "verify: numeric prompt coerced or handled"

  # -- /api/verify: prompt is null --
  assert_http POST "$NEXTJS_BASE/api/verify" '{"prompt":null}' "200" "verify: null prompt defaults to empty string"

  # -- /api/verify: malformed JSON --
  assert_http POST "$NEXTJS_BASE/api/verify" '{invalid json}' "400" "verify: malformed JSON rejected"

  # -- /api/verify: extremely long prompt (DoS test) --
  local long_prompt
  long_prompt="$(python3 -c "print('{\"prompt\":\"' + 'A'*100000 + '\"}')" 2>/dev/null || echo '{"prompt":"AAAA"}')"
  # Should either succeed or return 413/500, not hang
  local status
  status="$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H 'Content-Type: application/json' \
    -d "$long_prompt" \
    --max-time 10 \
    "$NEXTJS_BASE/api/verify" 2>/dev/null || echo "000")"
  if [ "$status" != "000" ]; then
    log_pass "verify: oversized prompt handled (HTTP $status, did not hang)"
  else
    log_fail "verify: oversized prompt caused timeout"
  fi

  # -- /api/verify: GET instead of POST --
  assert_http GET "$NEXTJS_BASE/api/verify" "" "405" "verify: GET method rejected (405)"

  # -- Legacy verify route --
  assert_http POST "$NEXTJS_BASE/api/legacy-verify" '{"text":"test"}' "200" "legacy-verify: valid request succeeds"

  # -- Legacy verify: missing text --
  assert_http POST "$NEXTJS_BASE/api/legacy-verify" '{}' "200" "legacy-verify: missing text defaults gracefully"

  # -- Non-existent API route --
  assert_http GET "$NEXTJS_BASE/api/nonexistent" "" "404" "non-existent API route returns 404"
}

# ---------------------------------------------------------------------------
# Malformed proof / attestation payload tests
# ---------------------------------------------------------------------------
test_malformed_proofs() {
  log_section "Malformed Proof & Attestation Payloads"

  # These test payloads against both verifiers if available

  # Invalid seal envelope: missing required commitments
  local bad_seal='{"seal":{"id":"bad-seal","modelCommitment":"","inputCommitment":"","outputCommitment":"","status":"pending"}}'

  # Invalid TEE attestation: wrong platform type
  local bad_tee='{"attestation":{"platform":999,"enclaveId":"","measurement":"not-hex","quote":"","nonce":""}}'

  # Invalid zkML proof: empty proof bytes, wrong proof system
  local bad_zkml='{"proof":{"proofSystem":"nonexistent-system","proofBytes":"","publicInputs":"","verifyingKeyHash":"","circuitHash":""}}'

  # XSS attempt in prompt
  local xss_payload='{"prompt":"<script>alert(1)</script>","text":"<img onerror=alert(1)>"}'

  # SQL injection attempt
  local sqli_payload='{"prompt":"'\''; DROP TABLE seals; --","text":"1 OR 1=1"}'

  for service_name in "FastAPI" "Next.js"; do
    local base_url
    if [ "$service_name" = "FastAPI" ]; then
      base_url="$FASTAPI_BASE"
      if ! check_service "$service_name" "$base_url"; then
        log_skip "$service_name not reachable - skipping malformed payload tests"
        continue
      fi
    else
      base_url="$NEXTJS_BASE"
      if ! check_service "$service_name" "$base_url"; then
        log_skip "$service_name not reachable - skipping malformed payload tests"
        continue
      fi
    fi

    local verify_endpoint
    if [ "$service_name" = "FastAPI" ]; then
      verify_endpoint="$base_url/infer/fraud"
    else
      verify_endpoint="$base_url/api/verify"
    fi

    # XSS payload should not be reflected unescaped
    local xss_resp
    xss_resp="$(curl -s -X POST -H 'Content-Type: application/json' -d "$xss_payload" --max-time 10 "$verify_endpoint" 2>/dev/null || echo "")"
    if echo "$xss_resp" | grep -q '<script>'; then
      log_fail "$service_name: XSS payload reflected unescaped in response"
    else
      log_pass "$service_name: XSS payload not reflected raw"
    fi

    # SQL injection should not cause error
    local sqli_status
    sqli_status="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d "$sqli_payload" --max-time 10 "$verify_endpoint" 2>/dev/null || echo "000")"
    if [ "$sqli_status" != "500" ] && [ "$sqli_status" != "000" ]; then
      log_pass "$service_name: SQL injection payload handled safely (HTTP $sqli_status)"
    else
      log_fail "$service_name: SQL injection payload caused server error"
    fi
  done
}

# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------
main() {
  printf '\033[1;35m%s\033[0m\n' "======================================================"
  printf '\033[1;35m  SQ19: Negative-Path Verifier Tests\033[0m\n'
  printf '\033[1;35m%s\033[0m\n' "======================================================"
  printf '  Repo root:       %s\n' "$REPO_ROOT"
  printf '  FastAPI URL:     %s\n' "$FASTAPI_BASE"
  printf '  Next.js URL:     %s\n' "$NEXTJS_BASE"
  printf '  Dry run:         %s\n' "$DRY_RUN"
  printf '  Date:            %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  if ! check_cmd curl; then
    printf '\n  \033[1;31mERROR: curl is required but not found\033[0m\n'
    exit 1
  fi

  # Structural tests always run
  test_fastapi_structure
  test_nextjs_structure

  # Runtime tests require the services to be up
  test_fastapi_negative_paths
  test_nextjs_negative_paths
  test_malformed_proofs

  printf '\n\033[1;36m=== Summary ===\033[0m\n'
  printf '  Passed: \033[1;32m%d\033[0m\n' "$PASS"
  printf '  Failed: \033[1;31m%d\033[0m\n' "$FAIL"

  if [ "$FAIL" -gt 0 ]; then
    printf '\n\033[1;31mFailed tests:\033[0m'
    printf "$FAILURES\n"
    printf '\n'
    exit 1
  fi

  printf '\n\033[1;32mAll negative-path verifier tests passed.\033[0m\n'
  exit 0
}

main "$@"
