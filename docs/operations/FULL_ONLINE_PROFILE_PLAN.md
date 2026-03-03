# Full-Online SDK Restoration Plan

## Purpose
This plan restores the two SDK crates from strict offline stubs to full online functionality once network access and `vendor/` refresh are available.

## Scope
1. `sdk/aethelred-sdk`
2. `sdk/aethelred-py`

## Profile Files
1. Offline manifests:
- `sdk/aethelred-sdk/Cargo.offline.toml`
- `sdk/aethelred-py/Cargo.offline.toml`

2. Full-online manifests:
- `sdk/aethelred-sdk/Cargo.full-online.toml`
- `sdk/aethelred-py/Cargo.full-online.toml`

3. Profile switch script:
- `scripts/switch_sdk_profile.sh`

## Current Behavior
1. Offline mode uses lightweight stubs by default.
2. Full implementations are preserved in:
- `sdk/aethelred-sdk/src/lib_full.rs`
- `sdk/aethelred-py/src/lib_full.rs`

## Activation Steps (When Online)
1. Switch to full-online manifests:
```bash
scripts/switch_sdk_profile.sh full-online
```

2. Refresh vendor for all Rust crates and SDKs:
```bash
scripts/switch_sdk_profile.sh full-online --vendor
```

3. Validate both SDK crates:
```bash
scripts/switch_sdk_profile.sh full-online --validate
```

## Rollback Steps
1. Restore strict offline manifests:
```bash
scripts/switch_sdk_profile.sh offline
```

2. Validate offline mode explicitly:
```bash
cd sdk/aethelred-sdk && cargo check --offline
cd sdk/aethelred-py && cargo check --offline
```

## Acceptance Criteria
1. `cargo check` succeeds in `sdk/aethelred-sdk` with full-online manifest.
2. `cargo check` succeeds in `sdk/aethelred-py` with full-online manifest.
3. `vendor/` contains all packages needed by both SDK crates.
4. Rollback to offline profile is one-command and reproducible.
