#!/usr/bin/env bash
# vendor-fuzz-deps.sh — Vendor fuzz-only dependencies (libfuzzer-sys and transitive deps)
# into the repo's vendor/ directory WITHOUT deleting .cargo/config.toml.
#
# This preserves the supply-chain policy: all Rust builds use vendored sources.
# The script temporarily suspends vendor source replacement so that cargo can
# resolve new deps from crates.io, vendors them into vendor/, then restores
# the config. After this script runs, fuzz crates compile under the normal
# vendored configuration.
#
# Usage (local bootstrap):
#   ./scripts/vendor-fuzz-deps.sh
#
# Usage (CI):
#   Called automatically by .github/workflows/fuzzing-ci.yml
#
# Supply-chain policy note:
#   This script is the ONLY sanctioned way to add fuzz deps to vendor/.
#   It does NOT delete .cargo/config.toml for the build — it temporarily
#   suspends it for the `cargo vendor` resolution step only, then restores
#   it before any compilation occurs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR_DIR="${REPO_ROOT}/vendor"
CARGO_CONFIGS=(
    "${REPO_ROOT}/.cargo/config.toml"
    "${REPO_ROOT}/crates/.cargo/config.toml"
)

# Check if all fuzz deps are already vendored
REQUIRED_DEPS=("libfuzzer-sys" "clap" "dashmap")
all_present=true
for dep in "${REQUIRED_DEPS[@]}"; do
    if [ ! -d "${VENDOR_DIR}/${dep}" ]; then
        all_present=false
        break
    fi
done
if [ "$all_present" = true ]; then
    echo "[vendor-fuzz-deps] All fuzz dependencies already vendored, nothing to do."
    exit 0
fi

echo "[vendor-fuzz-deps] Vendoring fuzz dependencies into ${VENDOR_DIR}..."

# ── Back up cargo configs ──────────────────────────────────────────────
for cfg in "${CARGO_CONFIGS[@]}"; do
    if [ -f "$cfg" ]; then
        cp "$cfg" "${cfg}.vendor-bak"
    fi
done

# ── Restore helper (used by trap and explicit call) ────────────────────
configs_restored=false
restore_configs() {
    if [ "$configs_restored" = true ]; then return; fi
    configs_restored=true
    for cfg in "${CARGO_CONFIGS[@]}"; do
        if [ -f "${cfg}.vendor-bak" ]; then
            mv "${cfg}.vendor-bak" "$cfg"
        fi
    done
}
trap restore_configs EXIT

# ── Temporarily remove vendor source replacement ──────────────────────
# This allows `cargo vendor` to resolve deps from crates.io.
# The configs are restored immediately after vendoring, BEFORE any compilation.
for cfg in "${CARGO_CONFIGS[@]}"; do
    if [ -f "$cfg" ]; then
        rm "$cfg"
    fi
done

# ── Vendor from ALL fuzz crates in a single pass ─────────────────────────
# `cargo vendor --sync` merges deps from multiple manifests into one vendor
# directory. Without --sync, each call overwrites vendor/ with only that
# manifest's dep tree. The first manifest is the primary (--manifest-path),
# the rest are synced via --sync.
# All Rust manifests that share vendor/: fuzz crates + workspace + SDK.
# The primary manifest is first; the rest are synced via --sync.
FUZZ_MANIFESTS=(
    "${REPO_ROOT}/crates/core/fuzz/Cargo.toml"
    "${REPO_ROOT}/crates/bridge/fuzz/Cargo.toml"
    "${REPO_ROOT}/crates/consensus/fuzz/Cargo.toml"
    "${REPO_ROOT}/crates/vm/fuzz/Cargo.toml"
    "${REPO_ROOT}/crates/Cargo.toml"
    "${REPO_ROOT}/sdk/rust/Cargo.toml"
)

VENDOR_CMD=(cargo vendor --manifest-path "${FUZZ_MANIFESTS[0]}")
for ((i=1; i<${#FUZZ_MANIFESTS[@]}; i++)); do
    if [ -f "${FUZZ_MANIFESTS[$i]}" ]; then
        VENDOR_CMD+=(--sync "${FUZZ_MANIFESTS[$i]}")
    else
        echo "[vendor-fuzz-deps] WARNING: ${FUZZ_MANIFESTS[$i]} not found, skipping" >&2
    fi
done
VENDOR_CMD+=("${VENDOR_DIR}/")

echo "[vendor-fuzz-deps] Running: ${VENDOR_CMD[*]}"
"${VENDOR_CMD[@]}"

# ── Restore configs ───────────────────────────────────────────────────
restore_configs

# ── Verify ────────────────────────────────────────────────────────────
for dep in "${REQUIRED_DEPS[@]}"; do
    if [ -d "${VENDOR_DIR}/${dep}" ]; then
        echo "[vendor-fuzz-deps] OK: ${dep} vendored."
    else
        echo "[vendor-fuzz-deps] ERROR: ${dep} not found in vendor/ after vendoring." >&2
        exit 1
    fi
done

echo "[vendor-fuzz-deps] Done. All fuzz crates should now compile under vendored mode."
echo "[vendor-fuzz-deps] Verify: cargo check --manifest-path crates/core/fuzz/Cargo.toml"
