#!/usr/bin/env bash
set -euo pipefail

if ! command -v gh >/dev/null 2>&1; then
  echo "error: GitHub CLI (gh) is required" >&2
  exit 1
fi

if [[ $# -lt 1 ]]; then
  cat <<USAGE
Usage: scripts/setup_required_github_checks.sh <owner/repo> [branch ...]

Example:
  scripts/setup_required_github_checks.sh aethelred/aethelred main develop
USAGE
  exit 1
fi

REPO="$1"
shift || true
CONFIG_FILE="${CONFIG_FILE:-.github/branch-protection/required-checks.json}"

if [[ $# -eq 0 ]]; then
  BRANCHES=(main develop)
else
  BRANCHES=("$@")
fi

if [[ ! -f "${CONFIG_FILE}" ]]; then
  echo "error: required checks config not found: ${CONFIG_FILE}" >&2
  exit 1
fi

checks_for_branch() {
  local branch="$1"

  if jq -e --arg branch "${branch}" '.[$branch] != null' "${CONFIG_FILE}" >/dev/null; then
    jq -c --arg branch "${branch}" '.[$branch]' "${CONFIG_FILE}"
    return
  fi

  while IFS= read -r pattern; do
    [[ "${pattern}" == "default" ]] && continue
    if [[ "${pattern}" == *"*"* ]] && [[ "${branch}" == ${pattern} ]]; then
      jq -c --arg pattern "${pattern}" '.[$pattern]' "${CONFIG_FILE}"
      return
    fi
  done < <(jq -r 'keys[]' "${CONFIG_FILE}")

  jq -c '.default' "${CONFIG_FILE}"
}

review_count_for_branch() {
  local branch="$1"
  if [[ "${branch}" == "main" ]]; then
    echo "2"
  else
    echo "1"
  fi
}

push_restrictions_for_branch() {
  local branch="$1"
  if [[ "${branch}" != "main" ]]; then
    echo "null"
    return
  fi

  local users_json teams_json
  users_json="$(jq -cn --arg user "${MAIN_PUSH_USER:-ramtamilselvan}" '[ $user ]')"
  teams_json="$(jq -cn --arg team "${MAIN_PUSH_TEAM:-core-admins}" '[ $team ]')"
  jq -cn --argjson users "${users_json}" --argjson teams "${teams_json}" '{users: $users, teams: $teams}'
}

for branch in "${BRANCHES[@]}"; do
  echo "Applying branch protection for ${REPO}:${branch}"
  contexts_json="$(checks_for_branch "${branch}")"
  review_count="$(review_count_for_branch "${branch}")"
  restrictions_json="$(push_restrictions_for_branch "${branch}")"
  echo "Required checks: ${contexts_json}"

  payload="$(jq -n \
    --argjson contexts "$contexts_json" \
    --argjson review_count "$review_count" \
    --argjson restrictions "$restrictions_json" \
    '{
      required_status_checks: {
        strict: true,
        contexts: $contexts
      },
      enforce_admins: true,
      required_pull_request_reviews: {
        dismiss_stale_reviews: true,
        require_code_owner_reviews: false,
        required_approving_review_count: $review_count
      },
      restrictions: $restrictions,
      required_conversation_resolution: true,
      allow_force_pushes: false,
      allow_deletions: false,
      block_creations: false,
      required_linear_history: true,
      lock_branch: false,
      allow_fork_syncing: false
    }'
  )"

  gh api \
    --method PUT \
    -H "Accept: application/vnd.github+json" \
    "/repos/${REPO}/branches/${branch}/protection" \
    --input - <<<"${payload}" >/dev/null

  echo "Done: ${branch}"
done
