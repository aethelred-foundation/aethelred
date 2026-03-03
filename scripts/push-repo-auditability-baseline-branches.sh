#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-push}"
if [[ "$MODE" != "push" && "$MODE" != "dry-run" ]]; then
  echo "usage: $0 [push|dry-run]" >&2
  exit 2
fi

# Resolve repo root relative to this script's location.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

declare -a REPOS=(
  "/tmp/aethelred-core-audit|codex/repo-authority-aeth-mr-001-20260224"
  "${REPO_ROOT}|codex/repo-authority-aeth-mr-001-20260224"
  "/tmp/aethelred-rust-node-audit|codex/aeth-mr-003-auditability-baseline-20260224"
  "${REPO_ROOT}/services/tee-worker|codex/aeth-mr-003-auditability-baseline-20260224"
  "${REPO_ROOT}/contracts|codex/aeth-mr-003-auditability-baseline-20260224"
  "${REPO_ROOT}/sdk|codex/aeth-mr-003-auditability-baseline-20260224"
  "${REPO_ROOT}/tools|codex/aeth-mr-003-auditability-baseline-20260224"
  "${REPO_ROOT}/integrations|codex/aeth-mr-003-auditability-baseline-20260224"
  "${REPO_ROOT}/frontend|codex/aeth-mr-003-auditability-baseline-20260224"
)

for entry in "${REPOS[@]}"; do
  repo="${entry%%|*}"
  branch="${entry##*|}"
  echo "=== ${repo}"
  if ! git -C "$repo" rev-parse --verify "$branch" >/dev/null 2>&1; then
    echo "missing branch: $branch" >&2
    exit 1
  fi
  remote="$(git -C "$repo" remote get-url origin)"
  head="$(git -C "$repo" rev-parse --short "$branch")"
  echo "remote: ${remote}"
  echo "branch: ${branch} (${head})"
  if [[ "$MODE" == "dry-run" ]]; then
    echo "dry-run: git -C \"$repo\" push -u origin \"$branch\""
  else
    git -C "$repo" push -u origin "$branch"
  fi
  echo
done
