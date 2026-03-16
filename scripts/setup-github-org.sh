#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_FILE="${MANIFEST_FILE:-$ROOT_DIR/docs/governance/github-repo-standards.json}"
LABELS_FILE="$(jq -r '.labels_file' "$MANIFEST_FILE")"
GITHUB_ORG="${GITHUB_ORG:-$(jq -r '.org' "$MANIFEST_FILE")}"
DEFAULT_BRANCH="${DEFAULT_BRANCH:-$(jq -r '.default_branch' "$MANIFEST_FILE")}"
ROLLOUT_MODE="${ROLLOUT_MODE:-branch}"
OPEN_PRS="${OPEN_PRS:-0}"
APPLY_LABELS="${APPLY_LABELS:-1}"
APPLY_BRANCH_PROTECTION="${APPLY_BRANCH_PROTECTION:-0}"
BRANCH_NAME="${BRANCH_NAME:-codex/github-standards-$(date +%Y%m%d)}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/setup-github-org.sh [repo-name ...]

Examples:
  scripts/setup-github-org.sh
  scripts/setup-github-org.sh contracts aethelred-sdk-ts

Environment:
  GITHUB_ORG                Override the GitHub org from the manifest
  DEFAULT_BRANCH            Default branch to target (default: main)
  ROLLOUT_MODE              branch|direct (default: branch)
  BRANCH_NAME               Branch name for rollout branches
  OPEN_PRS                  1 to open PRs automatically after pushing branches
  APPLY_LABELS              1 to sync labels (default), 0 to skip
  APPLY_BRANCH_PROTECTION   1 to apply branch protection to the canonical repo
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ "$ROLLOUT_MODE" != "branch" && "$ROLLOUT_MODE" != "direct" ]]; then
  echo "ROLLOUT_MODE must be branch or direct" >&2
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

gh auth status >/dev/null

REPOS=()
if [[ $# -gt 0 ]]; then
  REPOS=("$@")
else
  while IFS= read -r repo_name; do
    REPOS+=("$repo_name")
  done < <(jq -r '.repos[].name' "$MANIFEST_FILE")
fi

repo_json() {
  local name="$1"
  jq -cer --arg name "$name" '.repos[] | select(.name == $name)' "$MANIFEST_FILE"
}

repo_exists() {
  local repo="$1"
  gh repo view "${GITHUB_ORG}/${repo}" >/dev/null 2>&1
}

ensure_repo_exists() {
  local repo="$1"
  local description="$2"
  local homepage="$3"

  if repo_exists "$repo"; then
    return 1
  fi

  gh repo create "${GITHUB_ORG}/${repo}" \
    --public \
    --description "$description" \
    --homepage "$homepage" >/dev/null

  return 0
}

sync_topics() {
  local repo="$1"
  local topics_json="$2"
  local payload
  payload="$(jq -n --argjson names "$topics_json" '{names: $names}')"
  printf '%s\n' "$payload" | gh api \
    --method PUT \
    -H "Accept: application/vnd.github+json" \
    "repos/${GITHUB_ORG}/${repo}/topics" \
    --input - >/dev/null
}

sync_repo_metadata() {
  local repo="$1"
  local repo_payload="$2"
  local description homepage discussions
  description="$(printf '%s' "$repo_payload" | jq -r '.description')"
  homepage="$(printf '%s' "$repo_payload" | jq -r '.homepage')"
  discussions="$(printf '%s' "$repo_payload" | jq -r '.has_discussions')"

  gh repo edit "${GITHUB_ORG}/${repo}" \
    --description "$description" \
    --homepage "$homepage" \
    --default-branch "$DEFAULT_BRANCH" \
    --enable-issues >/dev/null

  if [[ "$discussions" == "true" ]]; then
    gh repo edit "${GITHUB_ORG}/${repo}" --enable-discussions >/dev/null
  fi

  sync_topics "$repo" "$(printf '%s' "$repo_payload" | jq -c '.topics')"
}

sync_labels() {
  local repo="$1"
  if [[ "$APPLY_LABELS" != "1" ]]; then
    return
  fi

  while IFS= read -r label_json; do
    local name color description
    name="$(printf '%s' "$label_json" | jq -r '.name')"
    color="$(printf '%s' "$label_json" | jq -r '.color')"
    description="$(printf '%s' "$label_json" | jq -r '.description')"
    gh label create "$name" \
      --repo "${GITHUB_ORG}/${repo}" \
      --color "$color" \
      --description "$description" \
      --force >/dev/null
  done < <(jq -c '.[]' "$ROOT_DIR/$LABELS_FILE")
}

stage_repo() {
  local repo="$1"
  local stage_dir="$2"
  bash "$ROOT_DIR/scripts/export-public-repo.sh" "$repo" "$stage_dir" >/dev/null
}

prepare_worktree() {
  local repo="$1"
  local worktree="$2"
  if gh repo clone "${GITHUB_ORG}/${repo}" "$worktree" -- --depth 1 >/dev/null 2>&1; then
    return 0
  fi

  mkdir -p "$worktree"
  git -C "$worktree" init >/dev/null
  git -C "$worktree" remote add origin "https://github.com/${GITHUB_ORG}/${repo}.git"
}

checkout_rollout_branch() {
  local worktree="$1"

  if git -C "$worktree" ls-remote --exit-code --heads origin "$BRANCH_NAME" >/dev/null 2>&1; then
    git -C "$worktree" fetch origin "$BRANCH_NAME" --depth 1 >/dev/null
    git -C "$worktree" switch -C "$BRANCH_NAME" FETCH_HEAD >/dev/null 2>&1 || git -C "$worktree" checkout -B "$BRANCH_NAME" FETCH_HEAD >/dev/null
    return
  fi

  git -C "$worktree" switch -C "$BRANCH_NAME" >/dev/null 2>&1 || git -C "$worktree" checkout -B "$BRANCH_NAME" >/dev/null
}

replace_worktree_contents() {
  local stage_dir="$1"
  local worktree="$2"
  find "$worktree" -mindepth 1 -maxdepth 1 ! -name '.git' -exec rm -rf {} +
  rsync -a "$stage_dir"/ "$worktree"/
}

create_pr_if_requested() {
  local repo="$1"
  if [[ "$OPEN_PRS" != "1" || "$ROLLOUT_MODE" != "branch" ]]; then
    return
  fi

  gh pr create \
    -R "${GITHUB_ORG}/${repo}" \
    --base "$DEFAULT_BRANCH" \
    --head "$BRANCH_NAME" \
    --title "chore: align GitHub standards and repo metadata" \
    --body "This rollout aligns the repository with the Foundation GitHub standards bundle, repo-role metadata, and current public source-of-truth model." >/dev/null || true
}

publish_repo() {
  local repo="$1"
  local repo_created="$2"
  local stage_dir="$3"
  local worktree
  worktree="$(mktemp -d)"

  prepare_worktree "$repo" "$worktree"
  if [[ "$repo_created" == "0" && "$ROLLOUT_MODE" == "branch" ]]; then
    checkout_rollout_branch "$worktree"
  fi

  replace_worktree_contents "$stage_dir" "$worktree"
  git -C "$worktree" add -A

  if git -C "$worktree" diff --cached --quiet; then
    echo "No content changes for ${GITHUB_ORG}/${repo}"
    rm -rf "$worktree"
    return
  fi

  git -C "$worktree" commit -m "chore: align GitHub standards and repo metadata" >/dev/null

  if [[ "$repo_created" == "1" || "$ROLLOUT_MODE" == "direct" ]]; then
    git -C "$worktree" push origin "HEAD:${DEFAULT_BRANCH}" >/dev/null
    echo "Pushed ${GITHUB_ORG}/${repo} to ${DEFAULT_BRANCH}"
  else
    git -C "$worktree" push -u origin "$BRANCH_NAME" >/dev/null
    echo "Pushed ${GITHUB_ORG}/${repo} to ${BRANCH_NAME}"
    create_pr_if_requested "$repo"
  fi

  rm -rf "$worktree"
}

for repo in "${REPOS[@]}"; do
  echo "Processing ${GITHUB_ORG}/${repo}"
  payload="$(repo_json "$repo")"
  description="$(printf '%s' "$payload" | jq -r '.description')"
  homepage="$(printf '%s' "$payload" | jq -r '.homepage')"

  repo_created="0"
  if ensure_repo_exists "$repo" "$description" "$homepage"; then
    repo_created="1"
    echo "Created ${GITHUB_ORG}/${repo}"
  fi

  sync_repo_metadata "$repo" "$payload"
  sync_labels "$repo"

  stage_dir="$(mktemp -d)"
  stage_repo "$repo" "$stage_dir"
  publish_repo "$repo" "$repo_created" "$stage_dir"
  rm -rf "$stage_dir"
done

if [[ "$APPLY_BRANCH_PROTECTION" == "1" ]]; then
  bash "$ROOT_DIR/scripts/setup_required_github_checks.sh" "${GITHUB_ORG}/aethelred" "$DEFAULT_BRANCH"
fi

echo
echo "Recommended pinned repos:"
jq -r '.pinned_repos[]' "$MANIFEST_FILE" | sed 's/^/- /'
