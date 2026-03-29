#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_FILE="${MANIFEST_FILE:-$ROOT_DIR/docs/governance/github-repo-standards.json}"
GITHUB_ORG="${GITHUB_ORG:-$(jq -r '.org' "$MANIFEST_FILE")}"
BRANCH_NAME="${BRANCH_NAME:-codex/github-standards-20260313}"
ROLLOUT_MODE="${ROLLOUT_MODE:-branch}"
OPEN_PRS="${OPEN_PRS:-1}"
APPLY_LABELS="${APPLY_LABELS:-0}"
APPLY_BRANCH_PROTECTION="${APPLY_BRANCH_PROTECTION:-0}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/resume-github-rollout.sh

Environment:
  GITHUB_ORG                Override org from manifest
  BRANCH_NAME               Rollout branch to update (default: codex/github-standards-20260313)
  ROLLOUT_MODE              branch|direct (default: branch)
  OPEN_PRS                  1 to open PRs when missing (default: 1)
  APPLY_LABELS              1 to sync labels, 0 to skip (default: 0)
  APPLY_BRANCH_PROTECTION   1 to apply branch protection at end (default: 0)
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required" >&2
  exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
  echo "GitHub CLI auth is not valid. Run: gh auth login -h github.com" >&2
  exit 1
fi

run_batch() {
  local label="$1"
  shift

  echo
  echo "== ${label} =="
  BRANCH_NAME="$BRANCH_NAME" \
  ROLLOUT_MODE="$ROLLOUT_MODE" \
  OPEN_PRS="$OPEN_PRS" \
  APPLY_LABELS="$APPLY_LABELS" \
  APPLY_BRANCH_PROTECTION=0 \
  bash "$ROOT_DIR/scripts/setup-github-org.sh" "$@"
}

run_batch "Org Control Plane" .github
run_batch "Canonical + Contracts" aethelred contracts
run_batch "SDKs + Tooling" \
  aethelred-sdk-ts \
  aethelred-sdk-py \
  aethelred-sdk-go \
  aethelred-sdk-rs \
  aethelred-cli \
  vscode-aethelred
run_batch "Docs + Governance + App" aethelred-docs AIPs cruzible

echo
echo "Manual pinned repos to set in the org profile UI:"
jq -r '.pinned_repos[] | "- " + .' "$MANIFEST_FILE"

echo
echo "After the PRs are merged, apply canonical branch protection with:"
echo "  bash scripts/setup_required_github_checks.sh ${GITHUB_ORG}/aethelred main"
