# Protocol Hardening Sweep — 2026-04-16

This note records the focused protocol hardening tranche prepared on top of
`main` for the current external full-protocol review window.

## Snapshot

- Repository: `aethelred-foundation/aethelred`
- Base branch at sweep start: `main`
- Base branch commit: `b66cb735c1`
- Hardening branch: `ramesh/protocol-hardening-sweep-20260416`
- Primary review PR: `#141`

## Scope of This Tranche

This sweep focused on audit-risk areas that could still produce high-severity
review findings even with the earlier repository and dependency hardening
already merged.

### 1. Bridge relayer safety and authority

- Replaced the previous no-op relayer storage shim with persisted state for
  block cursors, deposits, burns, and proposals in `crates/bridge/src/`.
- Tightened quorum math to round up instead of down.
- Required a configured relayer identity for proposal creation and stopped
  defaulting privileged actions to a zero proposer.
- Made placeholder vote generation, placeholder vote verification, and
  withdrawal submission paths fail closed instead of silently succeeding.
- Required the Aethelred burn parser to extract the real burn nonce from chain
  event attributes instead of fabricating `0`, preserving withdrawal-side
  monitoring and deduplication semantics.
- Tightened the Ethereum deposit log parser so malformed block hashes,
  transaction hashes, depositor topics, and log indexes are rejected instead
  of being silently normalized to zero values on the bridge ingress path.

### 2. VM, attestation, and consensus verification

- Prevented invalid attestation responses from satisfying slashable challenge
  flows in `crates/vm/src/system_contracts/slashing.rs`.
- Changed WASM host verification stubs to fail closed in
  `crates/vm/src/runtime/mod.rs`.
- Bound SGX and SEV attestation validation to the actual work-result hash in
  `crates/consensus/src/pouw/consensus.rs`.
- Enforced configured TEE measurement allowlists when present.
- Made incomplete SGX, Nitro, and SEV verifier backends return explicit errors
  in `services/tee-worker/nitro-sdk/src/attestation/` and mirrored the same
  fail-closed behavior in `sdk/aethelred-sdk/src/attestation/`.

### 2a. Hybrid signature runtime hardening

- Replaced the live placeholder hybrid signer/verifier logic in
  `services/tee-worker/nitro-sdk/src/crypto/hybrid.rs` with real
  secp256k1 ECDSA signing/verification and real Dilithium detached
  signing/verification for Levels 2, 3, and 5.
- Updated key and signature length handling to use the underlying Dilithium
  library sizes instead of stale hard-coded constants.
- Restricted deterministic `from_seed(...)` helpers to test builds so a
  pseudo-deterministic helper cannot be mistaken for a production key path.
- Mirrored the same signer/verifier logic in
  `sdk/aethelred-sdk/src/crypto/hybrid.rs` so the review surface no longer
  contains a stale placeholder copy of the same primitive.

### 2b. zk proof backend hardening

- Removed the placeholder zk proof generator in
  `services/tee-worker/nitro-sdk/src/zktensor/mod.rs` so the worker runtime no
  longer fabricates proof bytes, verifying keys, or circuit hashes.
- Changed `ZkTensor::generate_proof()`, `ZkTensor::verify()`, and
  `ProofVerifier::verify()` to return explicit backend-unavailable errors until
  a real EZKL-backed prover/verifier is wired in.
- Mirrored the same fail-closed proof contract in
  `sdk/aethelred-sdk/src/zktensor/mod.rs` and updated the most visible SDK/docs
  examples so the review surface no longer claims automatic proof generation
  where no backend exists.

### 3. Production governance bootstrap

- Restricted legacy direct-admin initializers to local-development chains for:
  - `contracts/contracts/AethelredBridge.sol`
  - `contracts/contracts/AethelredToken.sol`
  - `contracts/contracts/AethelredVesting.sol`
  - `contracts/contracts/vault/StAETHEL.sol`
  - `contracts/contracts/vault/VaultTEEVerifier.sol`
  - `contracts/contracts/vault/Cruzible.sol`
  - `contracts/contracts/InstitutionalStablecoinBridge.sol`
- Added or enforced `initializeWithTimelock(...)` production bootstraps so
  `UPGRADER_ROLE` is isolated to governance timelock from deployment day.
- Updated deployment scripts to emit governance calldata where post-deploy role
  mutation must happen through governance rather than a deployer key.

### 4. Cruzible deployability and reviewability

- Reduced `Cruzible.sol` deployed bytecode under the EIP-170 limit without
  weakening staking, delegation, reward, or verifier logic.
- Kept the production ABI lean and moved legacy test ergonomics into
  `contracts/test/helpers/CruzibleCompat.sol`.
- Cleaned the remaining upgrade-hook warning in
  `contracts/contracts/InstitutionalStablecoinBridge.sol`.

## Verification Completed

### Rust / bridge / VM / consensus / TEE

- `cargo test -p aethelred-bridge`
- `cargo test -p aethelred-vm test_invalid_attestation_response_does_not_satisfy_challenge`
- `cargo test -p aethelred-vm test_valid_sgx_attestation_satisfies_challenge`
- `cargo check -p aethelred-vm`
- `cargo test -p aethelred-consensus test_verification_engine`
- `cargo test -p aethelred-consensus test_verification_engine_tee_attestation`
- `cargo test -p aethelred-consensus test_verification_engine_rejects_sgx_measurement_not_in_allowlist`
- `cargo test -p aethelred-consensus test_verification_engine_rejects_tampered_sgx_binding`
- `cargo test --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features attestation-evidence fails_closed_when_backend_missing`
- `cargo check --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features attestation-evidence`
- `cargo check --manifest-path sdk/aethelred-sdk/Cargo.toml`
- `cargo test --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features full-sdk hybrid`
- `cargo test --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features full-sdk zktensor`
- `cargo check --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features full-sdk`

### Solidity / Hardhat / Foundry

- `npx hardhat compile`
- `npx hardhat size-contracts`
- `npx hardhat test` -> `61 passing`
- `forge test --match-path test/AethelredBridge.t.sol` -> `99 passed`
- `forge test --match-path test/AethelredVesting.t.sol` -> `104 passed`
- `forge test --match-path test/Cruzible.t.sol` -> `188 passed`
- `forge test --match-path test/CruzibleInvariant.t.sol` -> `13 passed`
- `forge test --match-path test/VaultInvariant.t.sol` -> `14 passed`

## Reviewer Notes

- The broad full `forge test` matrix was started as an extra confidence pass,
  but the authoritative validation for this tranche is the targeted Forge suites
  above plus the full `npx hardhat test` run, because those directly cover the
  affected bridge, governance, vault, and institutional paths.
- `Cruzible.sol` now measures `24,493` deployed bytes from the built artifact,
  and `npx hardhat size-contracts` reports `23.919 KiB`, returning the contract
  to mainnet-deployable range.
- This sweep is designed to reduce the risk of major findings in three areas
  auditors typically probe first: fail-open verifier behavior, direct-admin
  bootstrap windows, and bridge/relayer privilege ambiguity.
- The worker `zktensor` surface now fails closed instead of manufacturing proof
  material or returning verifier success without a backend, which removes a
  particularly visible claim-vs-control mismatch in the SDK runtime.
- The mirrored public SDK source was updated to match the hardened hybrid
  signer/verifier path and the fail-closed `zktensor` contract, but
  `cargo test --manifest-path sdk/aethelred-sdk/Cargo.toml
  --features full-sdk --lib hybrid` still fails because of pre-existing
  full-SDK crate drift outside this change set (missing dependencies/stubs,
  `lib_full.rs` doc-comment layout issues, and unrelated serde coverage gaps).
