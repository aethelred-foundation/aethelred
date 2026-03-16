#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SDK=""
OUT_DIR=""
TARGET_REPO=""
BRANCH=""
COMMIT_MESSAGE=""
PR_TITLE=""
PR_BODY=""
DO_VALIDATE="false"
DO_PUSH="false"
DO_CREATE_PR="false"

usage() {
  cat <<'USAGE'
Usage:
  sync-standalone-sdk.sh --sdk <typescript|rust> [options]

Options:
  --out-dir <path>          Export target directory (default: /tmp/aethelred-sdk-<kind>-sync)
  --validate                Run package validation in the exported repo
  --push-repo <owner/name>  Push exported repo to GitHub target repo (branch push)
  --branch <name>           Branch name to push (default: monorepo-sync-<sdk>-<timestamp>)
  --commit-message <msg>    Commit message for exported repo
  --create-pr               Create a PR after push (requires gh auth + --push-repo)
  --pr-title <title>        Optional PR title
  --pr-body <body>          Optional PR body

Examples:
  ./scripts/sync-standalone-sdk.sh --sdk typescript --validate
  ./scripts/sync-standalone-sdk.sh --sdk rust --validate --push-repo aethelred-foundation/aethelred-sdk-rust --create-pr
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sdk)
      SDK="${2:-}"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    --validate)
      DO_VALIDATE="true"
      shift
      ;;
    --push-repo)
      TARGET_REPO="${2:-}"
      DO_PUSH="true"
      shift 2
      ;;
    --branch)
      BRANCH="${2:-}"
      shift 2
      ;;
    --commit-message)
      COMMIT_MESSAGE="${2:-}"
      shift 2
      ;;
    --create-pr)
      DO_CREATE_PR="true"
      shift
      ;;
    --pr-title)
      PR_TITLE="${2:-}"
      shift 2
      ;;
    --pr-body)
      PR_BODY="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown arg: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$SDK" ]]; then
  echo "--sdk is required" >&2
  usage
  exit 1
fi

case "$SDK" in
  typescript)
    DEFAULT_OUT="/tmp/aethelred-sdk-js-sync"
    ;;
  rust)
    DEFAULT_OUT="/tmp/aethelred-sdk-rust-sync"
    ;;
  *)
    echo "Unsupported SDK: $SDK" >&2
    exit 1
    ;;
esac

OUT_DIR="${OUT_DIR:-$DEFAULT_OUT}"
BRANCH="${BRANCH:-monorepo-sync-${SDK}-$(date +%Y%m%d%H%M%S)}"
COMMIT_MESSAGE="${COMMIT_MESSAGE:-chore: sync ${SDK} SDK from monorepo}"
PR_TITLE="${PR_TITLE:-chore: sync ${SDK} SDK from monorepo}"
PR_BODY="${PR_BODY:-Automated export/sync from AethelredMVP monorepo.}"

echo "==> Exporting ${SDK} SDK to ${OUT_DIR}"
"$ROOT_DIR/scripts/export-sdk-standalone-repo.sh" "$SDK" "$OUT_DIR"

if [[ "$DO_VALIDATE" == "true" ]]; then
  echo "==> Validating exported ${SDK} SDK"
  if [[ "$SDK" == "typescript" ]]; then
    (
      cd "$OUT_DIR"
      export npm_config_cache="${NPM_CONFIG_CACHE:-/tmp/aethelred-npm-cache}"
      npm ci
      npm run build
      npm pack --dry-run --loglevel=error
    )
  else
    (
      cd "$OUT_DIR"
      cargo fmt --all -- --check
      cargo test --lib
      cargo package --no-verify --offline
    )
  fi
fi

if [[ "$DO_PUSH" == "true" ]]; then
  if [[ -z "$TARGET_REPO" ]]; then
    echo "--push-repo is required for push" >&2
    exit 1
  fi
  if [[ -z "${GH_TOKEN:-}" ]]; then
    echo "GH_TOKEN is required for push" >&2
    exit 1
  fi

  echo "==> Preparing git repo for push to ${TARGET_REPO}:${BRANCH}"
  (
    cd "$OUT_DIR"
    rm -rf .git
    git init
    git config user.name "aethelred-sync-bot"
    git config user.email "developers@aethelred.org"
    git add .
    git commit -m "$COMMIT_MESSAGE"
    git branch -M "$BRANCH"
    git remote add origin "https://x-access-token:${GH_TOKEN}@github.com/${TARGET_REPO}.git"
    git push -u origin "$BRANCH"
  )

  if [[ "$DO_CREATE_PR" == "true" ]]; then
    if ! command -v gh >/dev/null 2>&1; then
      echo "gh CLI not found; skipping PR creation"
    else
      echo "==> Creating PR in ${TARGET_REPO}"
      GH_TOKEN="$GH_TOKEN" gh pr create \
        --repo "$TARGET_REPO" \
        --base main \
        --head "$BRANCH" \
        --title "$PR_TITLE" \
        --body "$PR_BODY"
    fi
  fi
fi

echo "Done."
