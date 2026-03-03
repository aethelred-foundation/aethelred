#!/usr/bin/env bash
# =============================================================================
# Aethelred GitHub Org Setup Script — bash 3.2 compatible (macOS default)
# Usage: bash setup-github-org.sh
# Requires: gh (GitHub CLI) — brew install gh && gh auth login
# =============================================================================
set -euo pipefail

GITHUB_ORG="${GITHUB_ORG:-AethelredFoundation}"
REPO_ROOT="/Users/rameshtamilselvan/Downloads/aethelred"

echo "🚀 Setting up Aethelred GitHub org: $GITHUB_ORG"
echo "   Source: $REPO_ROOT"
echo ""

# -----------------------------------------------------------------------------
# STEP 1: Authenticate check
# -----------------------------------------------------------------------------
echo "📋 STEP 1: Verifying GitHub authentication..."
gh auth status || { echo "❌ Run: gh auth login"; exit 1; }
echo "✅ Authenticated"
echo ""

# -----------------------------------------------------------------------------
# STEP 2: Create all repositories
# -----------------------------------------------------------------------------
echo "📋 STEP 2: Creating GitHub repositories in $GITHUB_ORG..."

create_repo() {
  local name="$1"
  local desc="$2"
  echo "  Creating $GITHUB_ORG/$name..."
  gh repo create "$GITHUB_ORG/$name" \
    --public \
    --description "$desc" \
    --homepage "https://aethelred.io" \
    2>/dev/null && echo "  ✅ $name created" || echo "  ⚠️  $name already exists — skipping"
}

create_repo "aethelred"           "Core monorepo — Go node, Rust crates, Cosmos SDK modules (PoUW, Seal, Verify)"
create_repo "contracts"           "Production Solidity contracts — Ethereum bridge, Seal Verifier, wrapped AETHEL ERC-20"
create_repo "aethelred-sdk-ts"   "Official TypeScript / JavaScript SDK for the Aethelred blockchain"
create_repo "aethelred-sdk-py"   "Official Python SDK for the Aethelred blockchain"
create_repo "aethelred-sdk-go"   "Official Go SDK for the Aethelred blockchain"
create_repo "aethelred-sdk-rs"   "Official Rust SDK for the Aethelred blockchain"
create_repo "aethelred-cli"      "aeth — Command-line interface for the Aethelred blockchain"
create_repo "vscode-aethelred"   "VS Code extension for Aethelred development (AIP syntax, Seal verification, devnet)"
create_repo "aethelred-docs"     "Official documentation site for the Aethelred ecosystem"
create_repo "AIPs"                "Aethelred Improvement Proposals — protocol governance and standards"
create_repo ".github"             "Org-level profile and shared CI workflow templates"

echo ""
echo "✅ All repos created"
echo ""

# -----------------------------------------------------------------------------
# STEP 3: Initialize and push core monorepo
# -----------------------------------------------------------------------------
echo "📋 STEP 3: Initializing core monorepo git history..."
cd "$REPO_ROOT"

# Initialize git if not already a repo
if [ ! -d ".git" ]; then
  git init -b main
else
  echo "  Git already initialized. Adding any untracked files..."
fi

git add -A
git commit -m "feat: initial commit — Aethelred sovereign L1 for verifiable AI

- ABCI++ vote extensions with TEE + zkML verification (app/abci.go)
- x/pouw: Proof-of-Useful-Work module (scheduler, fee distribution, slashing)
- x/seal: Digital Seal module (on-chain AI computation attestation)
- x/verify: ZK proof verifier (EZKL, RISC0, Groth16, Halo2, Plonky2)
- AethelredBridge.sol: enterprise-grade Ethereum <-> Aethel bridge
- CI/CD: GitHub Actions (lint, test, security, release)
- AIPs: AIP-0001 (process), AIP-0002 (PoUW spec), AIP-0003 (Digital Seal)
- GoReleaser binary distribution config
- VSCode extension scaffold

Signed-off-by: Aethelred Team <team@aethelred.io>" 2>/dev/null || echo "  Nothing new to commit"

# Set remote (update if already exists)
git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/$GITHUB_ORG/aethelred.git"
git push -u origin main
echo "✅ Core monorepo pushed → https://github.com/$GITHUB_ORG/aethelred"
echo ""

# -----------------------------------------------------------------------------
# STEP 4: Push satellite repos from subdirectories
# -----------------------------------------------------------------------------
echo "📋 STEP 4: Pushing satellite repos..."

push_subdir() {
  local src_dir="$1"
  local repo_name="$2"
  local commit_msg="$3"

  if [ ! -d "$src_dir" ]; then
    echo "  ⚠️  $src_dir not found — skipping $repo_name"
    return
  fi

  echo "  Pushing $repo_name from $src_dir..."
  local tmpdir
  tmpdir=$(mktemp -d)
  cp -r "$src_dir/." "$tmpdir/"
  cd "$tmpdir"
  git init -b main
  git add -A
  git commit -m "$commit_msg

Signed-off-by: Aethelred Team <team@aethelred.io>" 2>/dev/null || true
  git remote add origin "https://github.com/$GITHUB_ORG/$repo_name.git"
  git push -u origin main --force
  cd "$REPO_ROOT"
  rm -rf "$tmpdir"
  echo "  ✅ $repo_name pushed → https://github.com/$GITHUB_ORG/$repo_name"
}

push_subdir "$REPO_ROOT/contracts"              "contracts"          "feat: initial commit — Solidity bridge and oracle contracts"
push_subdir "$REPO_ROOT/sdk/typescript"         "aethelred-sdk-ts"   "feat: initial commit — TypeScript SDK"
push_subdir "$REPO_ROOT/sdk/python"             "aethelred-sdk-py"   "feat: initial commit — Python SDK"
push_subdir "$REPO_ROOT/sdk/go"                 "aethelred-sdk-go"   "feat: initial commit — Go SDK"
push_subdir "$REPO_ROOT/sdk/rust"               "aethelred-sdk-rs"   "feat: initial commit — Rust SDK"
push_subdir "$REPO_ROOT/tools/vscode-aethelred" "vscode-aethelred"   "feat: initial commit — VS Code extension scaffold"

# AIPs repo from docs/AIPs/
echo "  Pushing AIPs..."
tmpdir=$(mktemp -d)
cp -r "$REPO_ROOT/docs/AIPs/." "$tmpdir/"
cd "$tmpdir"
git init -b main
git add -A
git commit -m "feat: initial commit — AIP-0001 (process), AIP-0002 (PoUW spec), AIP-0003 (Digital Seal)

Signed-off-by: Aethelred Team <team@aethelred.io>"
git remote add origin "https://github.com/$GITHUB_ORG/AIPs.git"
git push -u origin main --force
cd "$REPO_ROOT"
rm -rf "$tmpdir"
echo "  ✅ AIPs pushed → https://github.com/$GITHUB_ORG/AIPs"

# Org profile (.github)
echo "  Pushing org profile (.github)..."
tmpdir=$(mktemp -d)
mkdir -p "$tmpdir/profile"
cp "$REPO_ROOT/docs/github-org-profile/README.md" "$tmpdir/profile/"
cd "$tmpdir"
git init -b main
git add -A
git commit -m "feat: org profile README — Aethelred ecosystem overview

Signed-off-by: Aethelred Team <team@aethelred.io>"
git remote add origin "https://github.com/$GITHUB_ORG/.github.git"
git push -u origin main --force
cd "$REPO_ROOT"
rm -rf "$tmpdir"
echo "  ✅ Org profile pushed → https://github.com/$GITHUB_ORG/.github"
echo ""

# -----------------------------------------------------------------------------
# STEP 5: Set branch protection on core monorepo
# -----------------------------------------------------------------------------
echo "📋 STEP 5: Setting branch protection on main..."
gh api "repos/$GITHUB_ORG/aethelred/branches/main/protection" \
  -X PUT \
  --input - <<'JSON' 2>/dev/null && echo "✅ Branch protection set" || echo "⚠️  Branch protection skipped (may need admin token scope)"
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["go-test", "go-lint", "go-build", "rust-test"]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
echo ""

# -----------------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------------
echo "🎉 All done! Visit: https://github.com/orgs/$GITHUB_ORG/repositories"
echo ""
echo "📌 Manual steps remaining:"
echo "   1. Pin repos: aethelred, contracts, AIPs, aethelred-sdk-ts, vscode-aethelred"
echo "      → https://github.com/orgs/$GITHUB_ORG/repositories"
echo "   2. Enable Discussions on aethelred repo"
echo "   3. Add org avatar/banner"
echo "      → https://github.com/organizations/$GITHUB_ORG/settings/profile"
echo "   4. Add org secrets (CODECOV_TOKEN, DOCKER_TOKEN, NPM_TOKEN, PYPI_TOKEN):"
echo "      → https://github.com/organizations/$GITHUB_ORG/settings/secrets/actions"
