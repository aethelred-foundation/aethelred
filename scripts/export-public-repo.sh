#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_FILE="${MANIFEST_FILE:-$ROOT_DIR/docs/governance/github-repo-standards.json}"
ORG="$(jq -r '.org' "$MANIFEST_FILE")"

usage() {
  cat <<'USAGE'
Usage:
  scripts/export-public-repo.sh <repo-name> [output-dir]

Examples:
  scripts/export-public-repo.sh contracts /tmp/contracts
  scripts/export-public-repo.sh aethelred-sdk-ts /tmp/aethelred-sdk-ts
  scripts/export-public-repo.sh .github /tmp/aethelred-github
USAGE
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit 1
fi

REPO_NAME="$1"
OUT_DIR="${2:-}"

REPO_JSON="$(jq -cer --arg name "$REPO_NAME" '.repos[] | select(.name == $name)' "$MANIFEST_FILE")" || {
  echo "Unknown repo in manifest: $REPO_NAME" >&2
  exit 1
}

if [[ -z "$OUT_DIR" ]]; then
  SAFE_NAME="$(printf '%s' "$REPO_NAME" | tr '/.' '--')"
  OUT_DIR="/tmp/${SAFE_NAME}"
fi

ROLE="$(printf '%s' "$REPO_JSON" | jq -r '.role')"
SOURCE_PATH="$(printf '%s' "$REPO_JSON" | jq -r '.source_path')"
RELEASE_AUTHORITY="$(printf '%s' "$REPO_JSON" | jq -r '.release_authority')"
SPECIAL_EXPORT="$(printf '%s' "$REPO_JSON" | jq -r '.special_export // ""')"
DATE_STAMP="$(date -u +%Y-%m-%d)"
DEFAULT_CODEOWNERS="$(jq -r '.default_codeowners | join(" ")' "$MANIFEST_FILE")"

copy_if_missing() {
  local src="$1"
  local dst="$2"
  mkdir -p "$(dirname "$dst")"
  if [[ ! -e "$dst" ]]; then
    cp "$src" "$dst"
  fi
}

write_file_if_missing() {
  local dst="$1"
  local content="$2"
  mkdir -p "$(dirname "$dst")"
  if [[ ! -e "$dst" ]]; then
    printf '%s' "$content" > "$dst"
  fi
}

prepend_authority_notice() {
  local readme="$1"
  local notice
  notice="> Repo role: ${ROLE}
> Monorepo source path: \`${SOURCE_PATH}/\` in \`${ORG}/aethelred\`
> Canonical public source of truth: \`${ORG}/aethelred\`

"

  if [[ -f "$readme" ]]; then
    if grep -Eiq 'source of truth|exported from|repo role' "$readme"; then
      return
    fi
    local tmp
    tmp="$(mktemp)"
    printf '%s' "$notice" > "$tmp"
    cat "$readme" >> "$tmp"
    mv "$tmp" "$readme"
    return
  fi

  write_file_if_missing "$readme" "${notice}# ${REPO_NAME}

This repository is maintained as part of the Aethelred public GitHub standards
program.
"
}

write_codeowners() {
  local dst="$1"
  write_file_if_missing "$dst" "# Managed by scripts/export-public-repo.sh
* ${DEFAULT_CODEOWNERS}
"
}

write_repo_role_manifest() {
  local dst="$1"
  local json
  json="$(jq -n \
    --arg repo "${ORG}/${REPO_NAME}" \
    --arg role "$ROLE" \
    --arg source_path "$SOURCE_PATH" \
    --arg updated_at "$DATE_STAMP" \
    --arg canonical_repo "${ORG}/aethelred" \
    --argjson release_authority "$RELEASE_AUTHORITY" \
    '{
      version: 1,
      repo: $repo,
      role: $role,
      status: "active",
      canonical_public_source: $canonical_repo,
      monorepo_source_path: $source_path,
      exported_from_monorepo: true,
      release_authority: $release_authority,
      default_community_files_repo: ($repo | split("/")[0] + "/.github"),
      updated_at: $updated_at
    }')"
  printf '%s\n' "$json" > "$dst"
}

write_repo_security_policy() {
  local dst="$1"
  write_file_if_missing "$dst" "# Security Policy

This repository (\`${ORG}/${REPO_NAME}\`) follows the Aethelred Foundation
security program.

- Canonical public source: \`${ORG}/aethelred\`
- Repo role: \`${ROLE}\`
- Monorepo source path: \`${SOURCE_PATH}/\`

## Reporting A Vulnerability

Do not open public issues for vulnerabilities.

Email [security@aethelred.io](mailto:security@aethelred.io) with:

- affected repository and version or commit
- impact summary
- reproduction steps or proof-of-concept
- suggested mitigations if known

## Additional References

- Canonical security policy: [aethelred-foundation/aethelred/SECURITY.md](https://github.com/aethelred-foundation/aethelred/blob/main/SECURITY.md)
- Release provenance: [docs/security/release-provenance.md](docs/security/release-provenance.md)
"
}

write_repo_threat_model() {
  local dst="$1"
  write_file_if_missing "$dst" "# Threat Model

Status: Baseline
Repo: \`${ORG}/${REPO_NAME}\`
Role: \`${ROLE}\`
Canonical public source: \`${ORG}/aethelred\`
Monorepo source path: \`${SOURCE_PATH}/\`

## In Scope

- Code and configuration published in this repository
- Build and release workflow for this repository's surface area
- Dependency and packaging risk for this repository's artifacts

## Primary Risks

- Supply-chain or dependency compromise
- Release provenance drift from the canonical monorepo
- Incomplete security disclosures or stale support metadata
- Surface-specific logic or configuration bugs

## Required Controls

- Repo role and provenance declared in \`repo-role.json\`
- Security disclosures routed through \`SECURITY.md\`
- CI or baseline workflow coverage for docs and SBOM generation
"
}

write_repo_release_provenance() {
  local dst="$1"
  write_file_if_missing "$dst" "# Release Provenance

This repository is a public distribution surface for \`${ORG}/aethelred\`.

- Repo: \`${ORG}/${REPO_NAME}\`
- Role: \`${ROLE}\`
- Canonical public source: \`${ORG}/aethelred\`
- Monorepo source path: \`${SOURCE_PATH}/\`

Releases for this surface must map back to reviewed source in the canonical
monorepo and include the relevant tag, commit SHA, and changelog context.
"
}

write_origin_notice() {
  local dst="$1"
  write_file_if_missing "$dst" "# Repository Export Origin

- Source repo: \`${ORG}/aethelred\`
- Source path: \`${SOURCE_PATH}/\`
- Repo role: \`${ROLE}\`
- Exported by: \`scripts/export-public-repo.sh\`
- Export date: \`${DATE_STAMP}\`
"
}

stage_org_profile_repo() {
  mkdir -p "$OUT_DIR"
  rm -rf "$OUT_DIR"
  mkdir -p "$OUT_DIR/profile" "$OUT_DIR/.github/ISSUE_TEMPLATE" "$OUT_DIR/.github/workflows"

  cp "$ROOT_DIR/docs/github-org-profile/README.md" "$OUT_DIR/profile/README.md"
  cp "$ROOT_DIR/docs/github-org-profile/banner-dark.svg" "$OUT_DIR/profile/banner-dark.svg"
  cp "$ROOT_DIR/docs/github-org-profile/banner-light.svg" "$OUT_DIR/profile/banner-light.svg"

  cp "$ROOT_DIR/CODE_OF_CONDUCT.md" "$OUT_DIR/CODE_OF_CONDUCT.md"
  cp "$ROOT_DIR/SUPPORT.md" "$OUT_DIR/SUPPORT.md"
  cp "$ROOT_DIR/SECURITY.md" "$OUT_DIR/SECURITY.md"
  cp "$ROOT_DIR/LICENSE" "$OUT_DIR/LICENSE"
  cp "$ROOT_DIR/docs/github-org-profile/defaults/CONTRIBUTING.md" "$OUT_DIR/CONTRIBUTING.md"
  cp "$ROOT_DIR/docs/github-org-profile/defaults/PULL_REQUEST_TEMPLATE.md" "$OUT_DIR/PULL_REQUEST_TEMPLATE.md"
  cp "$ROOT_DIR/docs/github-org-profile/defaults/ISSUE_TEMPLATE/bug_report.md" "$OUT_DIR/.github/ISSUE_TEMPLATE/bug_report.md"
  cp "$ROOT_DIR/docs/github-org-profile/defaults/ISSUE_TEMPLATE/feature_request.md" "$OUT_DIR/.github/ISSUE_TEMPLATE/feature_request.md"
  cp "$ROOT_DIR/docs/github-org-profile/defaults/ISSUE_TEMPLATE/config.yml" "$OUT_DIR/.github/ISSUE_TEMPLATE/config.yml"
  cp "$ROOT_DIR/.github/workflows/docs-hygiene.yml" "$OUT_DIR/.github/workflows/docs-hygiene.yml"

  cat > "$OUT_DIR/README.md" <<'EOF'
# Aethelred GitHub Defaults

This repository provides the public GitHub profile and org-wide community
default files for `aethelred-foundation`.

- `profile/README.md`: public org homepage
- `CODE_OF_CONDUCT.md`, `SUPPORT.md`, `SECURITY.md`: default community health files
- `.github/ISSUE_TEMPLATE/*`: default issue intake templates
EOF

  write_repo_role_manifest "$OUT_DIR/repo-role.json"
}

stage_standard_repo() {
  local src="$ROOT_DIR/$SOURCE_PATH"

  if [[ ! -d "$src" ]]; then
    echo "Missing source path for ${REPO_NAME}: $src" >&2
    exit 1
  fi

  rm -rf "$OUT_DIR"
  mkdir -p "$OUT_DIR"

  local rsync_args=(
    -a
    --delete
    --exclude '.git'
    --exclude 'node_modules'
    --exclude 'dist'
    --exclude 'target'
    --exclude '.pytest_cache'
    --exclude '__pycache__'
    --exclude 'coverage'
    --exclude 'artifacts'
    --exclude 'cache'
    --exclude 'out'
  )

  if [[ "$ROLE" != "canonical-monorepo" ]]; then
    rsync_args+=(--exclude '.github')
  fi

  rsync "${rsync_args[@]}" "$src"/ "$OUT_DIR"/

  if [[ "$(printf '%s' "$REPO_JSON" | jq -r '.inject_standards')" == "true" ]]; then
    copy_if_missing "$ROOT_DIR/LICENSE" "$OUT_DIR/LICENSE"
    copy_if_missing "$ROOT_DIR/CODE_OF_CONDUCT.md" "$OUT_DIR/CODE_OF_CONDUCT.md"
    copy_if_missing "$ROOT_DIR/SUPPORT.md" "$OUT_DIR/SUPPORT.md"
    copy_if_missing "$ROOT_DIR/docs/github-org-profile/defaults/CONTRIBUTING.md" "$OUT_DIR/CONTRIBUTING.md"
    copy_if_missing "$ROOT_DIR/docs/github-org-profile/defaults/PULL_REQUEST_TEMPLATE.md" "$OUT_DIR/PULL_REQUEST_TEMPLATE.md"
    copy_if_missing "$ROOT_DIR/docs/github-org-profile/defaults/ISSUE_TEMPLATE/bug_report.md" "$OUT_DIR/.github/ISSUE_TEMPLATE/bug_report.md"
    copy_if_missing "$ROOT_DIR/docs/github-org-profile/defaults/ISSUE_TEMPLATE/feature_request.md" "$OUT_DIR/.github/ISSUE_TEMPLATE/feature_request.md"
    copy_if_missing "$ROOT_DIR/docs/github-org-profile/defaults/ISSUE_TEMPLATE/config.yml" "$OUT_DIR/.github/ISSUE_TEMPLATE/config.yml"
    copy_if_missing "$ROOT_DIR/.github/workflows/docs-hygiene.yml" "$OUT_DIR/.github/workflows/docs-hygiene.yml"
    copy_if_missing "$ROOT_DIR/.github/workflows/repo-security-baseline.yml" "$OUT_DIR/.github/workflows/repo-security-baseline.yml"
    write_codeowners "$OUT_DIR/CODEOWNERS"
    write_repo_security_policy "$OUT_DIR/SECURITY.md"
    write_repo_role_manifest "$OUT_DIR/repo-role.json"
    write_repo_threat_model "$OUT_DIR/docs/security/threat-model.md"
    write_repo_release_provenance "$OUT_DIR/docs/security/release-provenance.md"
    write_origin_notice "$OUT_DIR/REPO_SPLIT_ORIGIN.md"
    prepend_authority_notice "$OUT_DIR/README.md"
  fi
}

if [[ "$SPECIAL_EXPORT" == "org-profile" ]]; then
  stage_org_profile_repo
else
  stage_standard_repo
fi

echo "Exported ${REPO_NAME} to ${OUT_DIR}"
