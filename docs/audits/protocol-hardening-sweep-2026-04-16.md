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

### 2d. Simulated EZKL verifier integrity hardening

- Strengthened the local simulated EZKL verifier in
  `x/verify/ezkl/prover.go`, which previously accepted any well-formed
  `SimulatedEZKLProof` JSON payload after only shallow structural checks.
- Changed simulated proof generation and verification to share a deterministic
  proof transcript derived from `PublicInputs` and optional verifying-key
  material, then reject proofs whose commitments, evaluations, or challenges do
  not match that recomputed transcript.
- Added regression coverage proving that tampered simulated proofs and tampered
  public inputs now fail verification instead of silently succeeding.

### 2e. Validator slashing economic-penalty enforcement

- Tightened `x/validator/keeper/slashing.go`, where validator slashing
  previously updated only local slashing records, reputation, jail metadata,
  and tombstone state while leaving real economic slashing as a commented
  production follow-up.
- Added an explicit economic-penalty path that, when a staking keeper is
  configured, resolves the validator's consensus address and calls the real
  staking slash and jail hooks before any local slashing record is written.
- Made the keeper fail closed when that economic penalty cannot be resolved or
  applied, so invalid operator addresses, missing validators, missing
  consensus-address support, or slash/jail hook failures now abort the
  slashing flow instead of recording a misleading local-only penalty.
- Added regression coverage proving the keeper now invokes real slash/jail
  hooks when configured and preserves validator state when economic penalties
  cannot be applied.

### 2c. Keeper-side simulated attestation hardening

- Replaced the keeper's simulated TEE attestation success path in
  `x/verify/keeper/tee_verification_path.go`, which previously accepted
  platform-specific size checks as sufficient verification whenever
  `AllowSimulated=true`.
- Introduced an authenticated simulated-attestation quote envelope stored in
  `TEEAttestation.Quote`, keyed by an explicitly configured simulation verifier
  secret (`TEEConfig.RootCertificate`) in development and test environments.
- Bound the simulated attestation MAC to the attestation platform, enclave ID,
  measurement, user data, timestamp, certificate chain, nonce, and raw quote
  body so tampering any of those fields now invalidates verification.
- Preserved fail-closed production behavior: if `AllowSimulated=false`, the
  keeper still requires a configured remote attestation verifier endpoint and
  will not silently fall back to local success.
- Added regression coverage proving the keeper now rejects tampered simulated
  quotes and unconfigured simulation verifier keys while preserving replay
  protection and the normal dev/test success path.

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

### 3a. Automation keeper governance hardening

- Eliminated the deployer-owned bootstrap window in
  `contracts/contracts/InstitutionalReserveAutomationKeeper.sol`.
- The reserve automation keeper now takes its final owner at deployment instead
  of defaulting to the deployer and relying on a later ownership transfer.
- Updated `contracts/scripts/deploy-institutional-automation-keeper.ts` so the
  owner address is wired into constructor deployment directly, avoiding a
  post-deploy direct-admin window on a contract that can trigger reserve
  monitoring through pause-adjacent bridge roles.
- Added regression coverage proving that a configured governance owner controls
  the keeper immediately after deployment and the deployer cannot retain
  bootstrap authority.

### 3b. Deployment authority fail-closed hardening

- Centralized deployment authority resolution in
  `contracts/scripts/lib/deployment-governance.ts` so local-network fallbacks
  and non-local explicit-authority requirements are enforced consistently
  across protocol deployment scripts.
- Updated `contracts/scripts/deploy.ts` so non-local bridge deployments now
  require an explicit `ADMIN_ADDRESS`, and they can no longer silently backfill
  timelock proposers or executors from the deployer/admin path when a fresh
  governance timelock must be created.
- Updated `contracts/scripts/deploy-institutional-automation-keeper.ts` so
  non-local keeper deployments require an explicit `KEEPER_OWNER_ADDRESS`
  instead of defaulting to the deployer.
- Updated `contracts/scripts/deploy-cruzible.ts` so non-local deployments
  require explicit `ADMIN_ADDRESS`, `UPGRADER_TIMELOCK_ADDRESS`, and
  `TREASURY_ADDRESS`, matching the hardened timelock-first governance posture
  already enforced in the contracts themselves.
- Added targeted governance-config regression coverage proving the local
  fallback behavior remains available only for local deployments while
  non-local deployments fail closed when authority configuration is missing.

### 3c. Seal verifier fail-closed hardening

- Removed the claim-vs-control gap in `x/seal/keeper/verifier.go` where TEE
  attestations and zkML proofs were treated as verified after basic structural
  checks alone.
- The seal verifier now requires explicit TEE and zk verifier backends for
  production-facing verification and fails closed with explicit messages when
  those backends are not configured.
- Retained the legacy structural-only path only behind
  `AllowInsecureFallbackVerification`, making the insecure behavior opt-in for
  tests and local development instead of the production default.
- Updated the seal test suite so local fixtures opt into the insecure fallback
  explicitly, while new regressions prove the default config rejects both TEE
  and zk verification when no backend is configured.

### 3d. Mempool admission signature enforcement

- Replaced format-only hybrid signature acceptance in
  `crates/mempool/src/middleware/signature.rs`, where the live signature
  middleware previously treated structural signature markers and length checks
  as sufficient verification.
- The mempool now parses real hybrid public keys and signatures from serialized
  signed transactions, derives the sender from the presented public key, binds
  that sender to the signed transaction body, and verifies the transaction hash
  with the chain-aware hybrid verifier configuration from `aethelred-core`.
- Updated the mempool test suite to use real signed transactions from the core
  transaction path instead of mock signature blobs, and added a regression that
  proves tampering the serialized signature causes admission to fail.

### 3e. VM job-registry verification fail-closed enforcement

- Tightened `crates/vm/src/system_contracts/job_registry.rs` so the VM job
  registry no longer soft-accepts invalid TEE or zk verification precompile
  results on normal mainnet and testnet configuration paths.
- Added an explicit `require_cryptographic_verification` config gate to
  `JobConfig`, enabled by default for mainnet and testnet and disabled only
  for devnet scaffolding, so non-dev deployments now hard-fail when compiled
  verification backends reject, error, or are unavailable.
- Preserved the existing devnet-only permissive path for local scaffolding,
  while adding regressions that prove mainnet/testnet configs fail closed and
  the devnet compatibility lane still behaves intentionally.

### 3f. TEE precompile secure-by-default registry hardening

- Tightened `crates/vm/src/precompiles/tee.rs`,
  `crates/vm/src/precompiles/mod.rs`, and
  `crates/vm/src/precompiles/registry.rs` so the live VM precompile registry no
  longer wires in permissive TEE verifier defaults for mainnet-style runtime
  use.
- Changed the TEE verifier defaults to hardened enterprise presets and made the
  runtime registry explicitly install enterprise TEE precompile configurations
  instead of relying on softer helper defaults.
- Preserved an explicit `with_devnet()` constructor path for scaffolding tests
  so development-only structural verification behavior is isolated and no
  longer masquerades as the default runtime posture.
- Made the SGX, Nitro, and SEV platform-specific precompiles fail closed when
  real cryptographic verification backends are unavailable, eliminating
  placeholder success paths and signature-less SEV acceptance in the
  platform-specific addresses that sit alongside the universal TEE precompile.
- Added regression coverage proving the default precompile registry now rejects
  enterprise TEE verification without a real backend while the explicit devnet
  constructor still preserves the intended local-only permissive lane.

### 3g. Keeper-side simulated zk proof binding hardening

- Tightened `x/verify/keeper/zk_verification_path.go`, where the keeper’s
  simulated zk verification path previously accepted any proof blob that met a
  proof-system-specific minimum length when `AllowSimulated=true`.
- Replaced that shape-only acceptance with a deterministic simulated proof
  transcript bound to the proof system, public inputs, verifying key material,
  and circuit hash, so simulated proofs now fail if the proof bytes or public
  inputs are tampered.
- Updated `x/verify/keeper/registry_and_paths_test.go` to generate bound
  simulated proofs for the success path and to assert that both proof tampering
  and public-input tampering are rejected.

### 3h. Seal revocation workflow hardening

- Tightened `x/seal/keeper/revocation.go`, where revocation approval and
  execution previously treated request IDs as trusted inputs and allowed
  approval/execution flows to proceed without stored request state, dispute
  tracking, or approval-threshold enforcement.
- Added explicit in-manager request state so revocation requests are recorded,
  approvals are deduplicated per authority, approval thresholds are enforced,
  disputes transition the request into a blocked state, and dispute resolution
  deterministically restores or cancels the request.
- Made `ExecuteRevocation()` fail closed unless a stored request exists, the
  request is approved, the dispute window has elapsed, no unresolved disputes
  remain, and the target seal can still be revoked.
- Updated the seal keeper tests to exercise the full request -> approve ->
  execute and request -> dispute -> resolve paths instead of the former
  event-only placeholder flow.

### 3i. TEE startup fail-closed hardening

- Tightened `app/init_safe.go`, where the safe-initialization helper previously
  treated only literal `production` and `mainnet` TEE modes as critical.
- Real verifier-backed TEE modes such as `remote`, `http`, `nitro`, and
  `aws-nitro` now fail closed when client initialization cannot complete,
  instead of being classified as degradable and continuing under a misleading
  "simulation_mode" fallback posture.
- Added targeted regressions proving explicit simulated modes still initialize
  intentionally while real TEE modes without a usable verifier endpoint now
  return critical startup errors.

### 3j. Simulated Nitro client identity and artifact hardening

- Tightened `app/tee_client.go`, where the explicit `nitro-simulated` client
  previously identified itself as `aws-nitro`, emitted a quote format that did
  not match the app's Nitro schema validator, and generated zk proof bytes too
  short to satisfy the app's own proof-validation rules.
- The simulated Nitro client now identifies itself as `nitro-simulated`,
  produces schema-consistent simulated Nitro quote JSON with a simulation-only
  signature field, emits zk proof transcripts that satisfy app-layer proof
  validation, and reports simulated capabilities that keep
  `buildFullOrchestratorConfig()` on the intended simulated-verifier path.
- Updated the vote-extension and schema validation layer so explicit simulated
  platforms (`simulated`, `nitro-simulated`, `mock-tee`) are accepted only in
  permissive/dev validation lanes and are rejected consistently in strict
  production validation.

### 3k. Nitro payload encryption fail-closed hardening

- Tightened `x/verify/tee/nitro.go` and
  `services/tee-worker/l1-verifier/nitro.go`, where `EncryptForEnclave(...)`
  previously returned base64-wrapped plaintext while presenting itself as an
  enclave-encryption primitive.
- The simulated Nitro path now derives a real symmetric key from the configured
  simulation attestation secret and uses AES-GCM with bound associated data for
  authenticated encryption instead of a reversible encoding wrapper.
- The remote Nitro path now fails closed unless an attested enclave public-key
  encryption contract is actually available, instead of pretending plaintext has
  been protected.

### 3l. Seal signature verification fail-closed hardening

- Tightened `x/seal/keeper/verifier.go`, where the `signatures` check
  previously treated the mere presence of signature bytes as successful
  cryptographic verification.
- The seal verifier now follows the same backend discipline as the TEE and zkML
  checks: when signatures are present, verification fails closed unless an
  explicit signature verifier backend or an opt-in insecure test fallback is
  configured.
- Existing unsigned seal flows remain explicit and reviewable: if no
  attestation signatures are present, the verifier reports that there are no
  signatures to verify instead of pretending verification occurred.

### 3m. Seal export provenance fail-closed hardening

- Tightened `x/seal/keeper/export.go`, where `ExportOptions.AddExportSignature`
  previously exposed a signed-export control that was never actually enforced by
  the exporter implementation.
- Export signing now fails closed unless both an exporter address and an
  explicit export signer backend are configured.
- When a signer is configured, the exporter signs a deterministic payload that
  binds the exported seal content, verification summary, and export metadata
  instead of emitting an unsigned package with provenance-looking fields.

### 3n. PQC backend readiness honesty hardening

- Tightened `app/init_safe.go` and `app/pqc.go`, where the PQC availability
  check previously returned a placeholder `true` regardless of the requested
  PQC mode.
- Startup now distinguishes between simulated mode, which is allowed in the
  current build, and production or hybrid PQC modes, which honestly report the
  lack of a CIRCL-backed backend when it is not present.
- The graceful fallback behavior remains intact, but it no longer relies on a
  fake availability signal to get there.

### 3o. Enhanced seal signature fail-closed hardening

- Tightened `x/seal/keeper/verifier.go`, where `VerifyEnhancedSeal(...)`
  previously ignored the `EnhancedDigitalSeal.Signatures` surface entirely.
- Enhanced seal verification now fails closed when envelope signatures are
  present but no enhanced-signature verifier backend is configured, following
  the same backend discipline as the basic seal signature, TEE, and zk proof
  checks.
- Unsigned enhanced seals remain explicit and reviewable: the verifier reports
  that there are no enhanced signatures to verify instead of silently implying
  they were checked.

### 3p. Seal import provenance verification hardening

- Tightened `x/seal/keeper/export.go`, where `ImportFromBase64(...)`
  previously trusted decoded seal exports without verifying either the stored
  content hash or any attached export signature.
- Imported exports now re-compute the canonical content hash of the seal
  payload and reject tampering instead of silently accepting mutated audit
  artifacts.
- Signed exports now fail closed on import unless an explicit export signature
  verifier backend is configured, which makes export signing a real round-trip
  provenance control instead of a one-way decoration.

### 3q. TEE platform taxonomy alignment hardening

- Tightened `x/pouw/keeper/consensus.go`, where keeper-side vote-extension
  validation still treated only plain `simulated` as a simulated TEE platform
  and classified `nitro-simulated` or `mock-tee` as unknown.
- Production-mode keeper validation now treats all simulated TEE aliases as the
  same simulated class, so the app layer and PoUW keeper enforce one consistent
  production policy instead of drifting on platform naming.
- Tightened `app/vote_extension_signing.go` to reuse the canonical permissive
  `TEEAttestationData` validation rules, which means the application-level
  signature verifier no longer accepts arbitrary non-empty TEE platform names.

### 3r. ABCI vote-extension request binding hardening

- Tightened `app/abci.go`, where `VerifyVoteExtensionHandler()` previously
  trusted the vote extension's embedded validator address and height before
  cross-checking them against the authoritative consensus request.
- The ABCI ingress path now rejects vote extensions when the embedded
  `ValidatorAddress` does not exactly match `RequestVerifyVoteExtension`
  validator identity, preventing a mismatched extension from reaching staking
  lookup or signature verification under the wrong consensus identity.
- The ABCI ingress path now also rejects vote extensions whose embedded
  `Height` does not exactly match the consensus request height, closing another
  request-to-payload drift path before later aggregation logic.
- Tightened the test harness in `app/process_proposal_integration_test.go` so
  the lightweight app fixture now carries the PoUW KV-store key mapping needed
  for deterministic vote-extension time validation in focused ABCI tests.

### 3s. Runtime governance lock enforcement hardening

- Tightened `x/pouw/keeper/governance.go`, where `UpdateParams(...)`
  previously enforced only the `AllowSimulated` one-way gate even though the
  mainnet lock registry already described several other fields as locked or
  elevated-quorum-only.
- The generic runtime parameter-update path now fails closed on locked
  mainnet-governance fields such as `consensus_threshold`,
  `require_tee_attestation`, `allowed_proof_types`, and
  `slashing_penalty` instead of silently allowing authority-level updates that
  exceeded the guarantees described by the lock registry.
- The one-way disable path for `AllowSimulated` remains allowed so production
  chains can permanently tighten policy, but any other locked-parameter change
  now requires a dedicated elevated-governance execution path rather than the
  generic handler.
- Tightened `x/pouw/keeper/mainnet_params.go` so compatibility analysis and
  proposal-validation warnings now reflect the same fail-closed runtime truth:
  locked parameter changes are treated as requiring a dedicated override path,
  while one-way disabling `AllowSimulated` remains compatible.
- Added focused keeper regressions proving locked-parameter updates are
  rejected at runtime while mutable fields like `verification_reward` continue
  to update successfully.

### 3t. Governance compliance reporting alignment

- Tightened `x/pouw/keeper/security_compliance.go`, where the audit-facing
  verification policy and checklist previously treated the existence of the
  lock registry as sufficient evidence of governance change control.
- Compliance reporting now probes the live runtime governance lock policy and
  records success only when the generic update path actually rejects a locked
  parameter change, which aligns the audit surface with the fail-closed runtime
  enforcement added in the governance handler.
- Updated the audit checklist wording for parameter validation bounds so the
  documented consensus-threshold range now matches the code-enforced
  production bound of `[67,100]` instead of an outdated lower threshold.
- Added focused compliance regressions proving the policy assessment and audit
  checklist now reflect runtime enforcement rather than lock-registry metadata
  alone.

### 3u. Trusted-measurement registry mutation auditability

- Tightened `x/pouw/keeper/attestation_registry.go`, where privileged trust
  registry mutations previously updated the global TEE measurement registry
  without emitting a domain-specific event, without writing a structured audit
  record, and without distinguishing new registrations from duplicate or
  cleanup-only operations.
- Governance-authority appends now record whether the global registry entry was
  newly registered or already present, and Nitro appends also reconcile the
  legacy PCR0 compatibility index instead of silently leaving it stale.
- Security-committee revocations now fail closed only when neither the global
  registry nor the legacy Nitro compatibility index contains the measurement,
  and otherwise record the exact revocation or cleanup results for both
  indexes.
- Added focused registry regressions proving authority-driven appends reconcile
  legacy Nitro indexing, emergency committee revocations remove both trust
  indexes, and unknown revocations no longer report false success.

### 3v. Security audit and threat-model truth alignment

- Tightened `x/pouw/keeper/security_audit.go`, where the built-in audit runner
  still described the older `[51,100]` consensus-threshold range even though
  the hardened production posture and governance controls now require the
  stronger `67%+` supermajority floor.
- The audit runner now treats `ConsensusThreshold < 67` as a critical
  production finding, which aligns the repo’s self-audit surface with the
  actual mainnet governance posture instead of leaving auditors to reconcile
  conflicting thresholds across different internal reports.
- Tightened `x/pouw/keeper/threat_model.go` so the governance and vote
  extension attack surfaces now describe the real `UpdateParams` one-way gate,
  live runtime governance-lock enforcement, and the implemented app-layer vote
  extension signing path instead of older `MergeParams` or `TODO` narratives.
- Added focused audit-runner regressions proving the stricter production floor
  is enforced in the self-audit path and that the clean-state audit surface
  remains green.

### 3w. Trusted-measurement emergency revocation quorum enforcement

- Tightened `x/pouw/keeper/attestation_registry.go`, where a single
  security-committee member could still execute a trusted-measurement
  revocation immediately once they were inside the committee set.
- Emergency trusted-measurement revocation now uses a persisted request
  workflow: the first committee member creates the request and records an
  approval, duplicate approvals from the same committee member are rejected,
  and the registry mutation executes only after a second independent bonded
  committee member approves the same platform-qualified measurement.
- The committee set used for that workflow is now derived only from bonded
  validators, matching the documented "top bonded validators" authority model
  instead of loosely sorting the full validator list.
- Small or misconfigured committees fail closed: if fewer than two bonded
  committee members exist, emergency trusted-measurement revocation aborts
  instead of degrading to a unilateral kill switch.
- Added focused regressions proving request creation, duplicate-approval
  rejection, final approval execution, and single-member committee rejection
  all behave deterministically and emit a truthful runtime audit trail.

### 3x. Seal privileged revocation bypass removal

- Tightened `x/seal/keeper/revocation.go`, where privileged authorities could
  still bypass the request/dispute workflow through the direct `RevokeSeal(...)`
  helper even after the stored revocation-state hardening landed.
- Direct revocation is now reserved for the seal creator’s self-revocation
  path. Admin-level authorities are forced back onto the governed
  request/approval/execute workflow instead of revoking seals immediately by
  convenience call.
- Raised the default authority threshold in `DefaultRevocationConfig()` to
  `2`, so default privileged revocation now requires independent authority
  confirmation unless an explicit override config is chosen for a narrower
  environment.
- Tightened `x/seal/keeper/msg_server.go` so module authority can no longer use
  `MsgRevokeSeal` as an immediate revoke shortcut; governance-controlled
  revocation must now flow through the governed revocation workflow instead of
  bypassing dispute and approval controls on the direct message path.
- Removed the exported raw keeper revoke entrypoint from the normal review
  surface by narrowing it to an internal direct self-revocation helper instead
  of leaving an ungoverned direct revoke method on the keeper API.
- Preserved the explicit emergency lane, but now require non-empty
  justification for `EmergencyRevoke(...)`, require non-empty justification for
  emergency batch revocation too, and keep the direct forced path confined to
  emergency authority rather than ordinary admin authority.

### 3y. Seal emergency revocation quorum enforcement

- Tightened `x/seal/keeper/revocation.go`, where the remaining explicit
  emergency lane still allowed a single emergency authority to revoke a seal
  immediately for any reason once they were inside the emergency set.
- Emergency seal revocation now uses a quorumed break-glass workflow: the
  first emergency authority records a stored emergency request and approval,
  duplicate approvals are rejected, and execution occurs only after a second
  independent emergency authority approves the same request.
- The emergency lane is now restricted to genuinely urgent reasons
  (`fraud_detected`, `model_compromised`, `privacy_breach`,
  `compliance_violation`, `tee_compromised`, `legal_order`) instead of acting
  as a general-purpose override for ordinary lifecycle reasons such as
  `user_request`, `expired`, or `replaced`.
- Emergency requests no longer enter the ordinary dispute workflow. They remain
  an explicit break-glass path, but now emit approval-state evidence and fail
  closed until the configured emergency quorum is satisfied.
- Emergency batch revocation now follows the same quorumed path on a per-seal
  basis instead of executing a direct bypass for every target in the batch.

### 3z. Vault governance authority enforcement

- Tightened `x/vault/keeper/keeper.go`, where several exported keeper methods
  were documented as governance-only but still relied on call-site convention
  instead of explicit authority checks at the keeper boundary.
- `RegisterVendorRootKey(...)`, `RegisterEnclave(...)`,
  `RegisterOperator(...)`, `RevokeEnclave(...)`, `RevokeOperator(...)`,
  `RegisterAttestationRelay(...)`, `InitiateRelayRotation(...)`,
  `FinalizeRelayRotation(...)`, `CancelRelayRotation(...)`, and
  `RevokeRelay(...)` now all require the module authority explicitly instead of
  leaving that restriction as a comment-level assumption.
- Added focused regressions in `x/vault/keeper/keeper_test.go` proving those
  governance-only keeper paths reject non-authority callers before mutating any
  enclave, operator, root-key, or attestation-relay state.

### 3za. Vault relay challenge governance enforcement

- Tightened the attestation-relay liveness workflow in
  `x/vault/keeper/keeper.go`, where `ChallengeRelay(...)` was documented as a
  governance-issued control but still allowed arbitrary callers to mint or
  replace live relay challenges.
- `ChallengeRelay(...)` now enforces module authority directly, rejects
  in-place overwrite of live challenges, clears expired challenge state before
  rollover, and records both challenge issuance and successful response in the
  operator audit log.
- Added regressions in `x/vault/keeper/keeper_test.go` proving non-authority
  callers cannot issue relay challenges, live challenges cannot be silently
  replaced, expired challenge state is cleared, and governance can safely
  re-issue a fresh challenge after expiry.

### 3zb. Admin consensus-audit endpoint boundary hardening

- Tightened `app/consensus_evidence_handler.go`, where the
  `/admin/consensus/evidence/audit` route was mounted as an admin endpoint but
  still accepted unauthenticated requests from arbitrary remote addresses.
- The handler is now loopback-only by default, supports explicit bearer-token
  authorization through `AETHELRED_ADMIN_API_TOKEN` when intentionally exposed
  beyond loopback, and rejects oversized request bodies before decoding.
- Added focused regressions in `app/consensus_evidence_handler_test.go`
  covering off-loopback rejection, bearer-token authorization, invalid token
  rejection, and fast-fail oversized request handling.

### 3zc. Health endpoint truthfulness hardening

- Tightened `app/health.go`, where simulated or fallback-permitted verification
  paths could still collapse into an overall `healthy` report because the
  handler treated allowed simulation as component health.
- The health surface now reports `simulated` or `degraded` explicitly when the
  node is running in simulated mode or tolerating a degraded verification path,
  and it returns `503` only for genuinely unhealthy overall states instead of
  flattening all non-fatal fallback modes into `healthy`.
- Added focused regressions in `app/health_test.go` covering overall status
  precedence, simulated/degraded truthfulness, and HTTP status signaling.

### 3ze. Health endpoint detail redaction hardening

- Tightened `app/health.go` again so `/health/aethelred` can remain usable as a
  public liveness surface without exposing detailed internal readiness,
  capability, chain, and component diagnostic data to arbitrary remote callers.
- Detailed health output is now available only to loopback callers or requests
  authorized with `AETHELRED_HEALTH_API_TOKEN`. Untrusted remote callers still
  receive the honest top-level and per-component status, but chain ID, height,
  detailed component payloads, and component messages are redacted.
- Added focused regressions in `app/health_test.go` covering redaction behavior
  and detailed-view authorization.

### 3zd. Metrics endpoint boundary hardening

- Tightened `app/metrics_exporter.go`, where the `/metrics/aethelred` route was
  exposed without an explicit handler-level access boundary and relied on outer
  routing or deployment conventions for both method and network restriction.
- The metrics handler now enforces `GET` at the boundary, is loopback-only by
  default, and allows deliberate remote scraping only through
  `AETHELRED_METRICS_API_TOKEN` bearer-token authorization.
- Refactored the loopback-or-bearer guard into shared operational route auth so
  admin and metrics surfaces follow the same boundary model instead of drifting
  independently.
- Added focused regressions in `app/metrics_exporter_test.go` covering
  method rejection, off-loopback rejection, bearer-token authorization, invalid
  token rejection, and nil-app error behavior.

### 3zf. Forwarded operational-route boundary hardening

- Tightened `app/operational_route_auth.go`, where the shared
  loopback-or-bearer guard still trusted `RemoteAddr` alone and could
  accidentally treat proxied operational requests as local-only traffic.
- Direct loopback access is now allowed only when the request does not carry
  forwarding headers such as `Forwarded`, `X-Forwarded-For`, or `X-Real-IP`.
  Requests that arrive through a local proxy boundary must now use the same
  explicit bearer-token path as other remote callers before they can access
  detailed health data, metrics, or the admin consensus-audit endpoint.
- Added focused regressions in `app/consensus_evidence_handler_test.go`,
  `app/metrics_exporter_test.go`, and `app/health_test.go` covering forwarded
  loopback rejection without a token and successful access only through valid
  bearer-token authorization.

### 3zg. Remote TEE endpoint validation hardening

- Tightened `app/tee_client.go`, where `RemoteTEEClient` already validated the
  configured remote endpoint for execution and capability fetches but still
  allowed the health probe path to bypass the same SSRF guard.
- `NewRemoteTEEClient(...)` now validates the configured remote endpoint at
  construction time, so real remote TEE modes fail closed during startup if the
  configured endpoint is unsafe or malformed instead of deferring that failure
  until later runtime use.
- `RemoteTEEClient.IsHealthy(...)` now validates the derived `/health` URL
  before issuing the request and records the failure through the same
  fail-closed path used by the other remote TEE operations.
- Added focused regressions in `app/tee_client_test.go` covering invalid remote
  endpoint rejection at construction time and fail-closed health probing for a
  blocked endpoint.

### 3zh. Readiness endpoint probe validation hardening

- Tightened `x/verify/readiness.go`, where the startup reachability sweep still
  issued best-effort HTTP probes against configured verifier endpoints without
  first passing those URLs through the shared endpoint safety guard.
- The readiness probe now validates each derived probe URL with the same
  shared SSRF protection used by the remote verifier and app TEE paths, so
  blocked metadata hosts, private-address targets, and malformed endpoints are
  treated as unreachable instead of being probed at startup.
- Added focused regressions in `x/verify/readiness_test.go` covering blocked
  endpoint rejection and readiness classification of blocked verifier targets
  as unreachable without any network call succeeding.

### 3zi. EZKL remote endpoint validation hardening

- Tightened `x/verify/ezkl/prover.go`, where the remote EZKL prover and remote
  verifier paths still built outbound `/prove` and `/verify` requests directly
  from configured endpoints without first reusing the shared endpoint safety
  guard.
- `CallRemoteProver(...)` and `CallRemoteVerifier(...)` now validate their
  derived remote URLs before creating the HTTP request and fail closed through
  the prover/verifier circuit-breaker path when the configured endpoint is
  unsafe or malformed.
- Added focused regressions in `x/verify/ezkl/prover_remote_test.go` covering
  blocked metadata-host rejection for both remote proving and remote
  verification.

### 3zj. DCAP collateral endpoint validation hardening

- Tightened `x/verify/tee/dcap/verifier.go` and the mirrored
  `services/tee-worker/l1-verifier/dcap/verifier.go`, where the DCAP
  collateral fetch paths still created raw outbound requests for PCCS, TCB,
  QE identity, and CRL collateral without first reusing the shared endpoint
  safety guard.
- `DCAPVerifier.httpGet(...)` now validates collateral URLs before any outbound
  request is created, so malformed, metadata, and private-address targets fail
  closed through the existing circuit-breaker path instead of being probed
  directly during quote-collateral retrieval.
- `DCAPVerifier.fetchCRLFromIntel(...)` now applies the same validator to PCCS
  CRL fetches and CRL distribution-point fallbacks, so revocation collateral
  no longer bypasses the module's outbound endpoint safety contract.
- Added focused regressions in `x/verify/tee/dcap/verifier_security_test.go`
  covering blocked collateral endpoints and blocked CRL distribution-point
  URLs.

### 3zk. Worker Nitro endpoint validation hardening

- Tightened `services/tee-worker/l1-verifier/nitro.go`, where the mirrored
  worker-side Nitro remote executor and remote attestation verifier still
  constructed outbound requests directly from configured endpoints instead of
  enforcing the same endpoint safety contract already present in the
  chain-side Nitro path.
- `callRemoteExecutor(...)` and `callRemoteAttestationVerifier(...)` now
  validate their derived remote URLs before creating the HTTP request, so
  malformed, metadata, and private-address targets fail closed through the
  worker service's circuit-breaker path instead of being contacted directly.
- Those worker-side remote error paths now also bound HTTP error-body reads via
  the shared `httputil` limit, keeping the mirrored Nitro runtime aligned with
  the chain-side memory-pressure defense.
- Added focused regressions in `services/tee-worker/l1-verifier/nitro_test.go`
  covering blocked remote executor and attestation-verifier endpoints.

### 3zl. Drand relay boundary hardening

- Tightened `x/pouw/keeper/drand_pulse.go`, where the consensus-facing drand
  pulse provider still trusted configured relay endpoint shape implicitly even
  though that path can influence scheduler entropy and reach out to external
  infrastructure.
- `NewHTTPDrandPulseProvider(...)` now validates the configured drand relay
  endpoint with the shared endpoint safety guard and carries any failure
  forward so `LatestPulse(...)` fails closed on malformed, metadata, or
  private-address targets instead of probing them.
- The localhost JSON fallback now decodes through a bounded reader, so local
  test relay responses no longer have an unbounded body path compared with the
  stricter verifier surfaces elsewhere in the protocol.
- Added focused regressions in `x/pouw/keeper/drand_pulse_test.go` covering
  blocked relay endpoints and oversized local fallback payloads.

### 3zm. TEE worker backend proxy boundary hardening

- Tightened `services/tee-worker/executor/main.go`, where the worker's
  `/execute` and `/verify` proxy paths still forwarded to the configured
  backend URL without enforcing the same endpoint safety contract already used
  across the verifier stack.
- The worker now validates `AETHELRED_TEE_BACKEND_URL` at startup so obviously
  unsafe backend configuration fails closed before the service begins
  advertising a ready remote-execution surface.
- The runtime proxy path also validates the derived backend target before
  building the forwarded request, so direct server construction or drifted
  config cannot bypass the startup check and reach metadata or private-address
  targets.
- Added focused regressions in `services/tee-worker/executor/main_test.go`
  covering blocked backend endpoints for both `/execute` and `/verify`.

### 3zn. Lightweight attestation collateral fail-closed hardening

- Tightened `services/tee-worker/nitro-sdk/src/attestation/engine.rs`, where
  the lightweight attestation engine still fabricated empty Intel PCCS and AMD
  KDS collateral objects even though those collateral-fetch backends were not
  actually implemented in that engine path.
- `fetch_intel_collateral(...)` now fails closed with an explicit backend
  unavailability error that includes the extracted FMSPC context, instead of
  returning an empty-looking Intel collateral bundle.
- `fetch_amd_collateral(...)` now fails closed with an explicit AMD KDS backend
  unavailability error instead of returning an empty collateral structure.
- Added focused regressions in
  `services/tee-worker/nitro-sdk/src/attestation/engine.rs` covering both
  Intel and AMD lightweight-engine collateral paths under the
  `attestation-evidence` feature.

### 3zo. Nitro parser fail-closed hardening

- Tightened `services/tee-worker/nitro-sdk/src/attestation/aws_nitro.rs`,
  where the Nitro wrapper still returned a placeholder attestation document
  after only checking the outer COSE marker, leaving later verification steps
  to fail on fabricated empty fields.
- `parse_document(...)` now fails closed with an explicit
  `AwsNitro("Nitro COSE/CBOR parsing backend is not implemented")` error
  instead of constructing fake attestation state that could be mistaken for a
  partially parsed real document.
- Added a focused regression in
  `services/tee-worker/nitro-sdk/src/attestation/aws_nitro.rs` covering the
  fail-closed parse behavior under the `attestation-evidence` feature.

### 3zp. ARM attestation parser and signature fail-closed hardening

- Tightened `services/tee-worker/nitro-sdk/src/attestation/arm_trustzone.rs`,
  where the ARM TrustZone / CCA wrapper still relied on placeholder token
  parsing and signature-verification methods that returned success once a
  non-empty signature was present.
- `parse_cca_token(...)` and `parse_psa_token(...)` now fail closed with
  explicit backend-unavailable errors instead of fabricating placeholder token
  state.
- `verify_platform_signature(...)`, `verify_realm_signature(...)`, and
  `verify_tz_signature(...)` now fail closed with explicit
  `ArmTrustZone("...not implemented")` errors once signature presence has been
  checked, instead of returning `Ok(())` without real cryptographic
  verification.
- Added focused regressions in
  `services/tee-worker/nitro-sdk/src/attestation/arm_trustzone.rs` covering
  fail-closed parser and signature paths under the `attestation-evidence`
  feature.

### 3zq. Shared endpoint literal-IP fail-closed hardening

- Tightened `x/verify/httputil/httputil.go`, where the shared endpoint
  validator still relied too heavily on string prefix checks and DNS
  resolution, which left room for literal loopback or private-address forms to
  bypass the non-routable endpoint policy when supplied directly as endpoint
  hosts.
- `ValidateEndpointURL(...)` now requires a real host, preserves the
  localhost-only HTTP dev exception for the explicit local hosts
  (`localhost`, `127.0.0.1`, `::1`), and validates literal IP addresses
  directly so loopback, private, link-local, unspecified, and multicast
  addresses fail closed even when DNS is never consulted.
- Added focused regressions in `x/verify/httputil/httputil_test.go` covering
  explicit localhost allowances plus blocked literal IPv4/IPv6 bypass cases,
  including non-canonical loopback and private IPv6 forms.

### 3zr. Worker API loopback-or-bearer hardening

- Tightened `services/tee-worker/executor/main.go`, where the TEE worker
  control plane still relied on ambient network placement instead of
  code-enforced caller authentication for `/health`, `/capabilities`,
  `/execute`, and `/verify`.
- The worker now defaults to explicit loopback binding
  (`127.0.0.1:8545`), requires `AETHELRED_TEE_API_TOKEN` whenever it is bound
  beyond loopback, and enforces loopback-or-bearer authorization on all HTTP
  routes while refusing forwarded-header loopback trust.
- Tightened `app/tee_client.go` so `RemoteTEEClient` automatically presents the
  configured `AETHELRED_TEE_API_TOKEN` as a bearer token on health,
  capabilities, and execution requests when remote exposure is intentionally
  enabled.
- Added focused regressions in
  `services/tee-worker/executor/main_test.go` and `app/tee_client_test.go`
  covering remote request rejection without a bearer token, remote acceptance
  with the configured bearer token, and token-aware remote client health
  probing.

### 3zs. SGX TCB fail-closed hardening

- Tightened `services/tee-worker/nitro-sdk/src/attestation/intel_sgx.rs`,
  where the SGX TCB evaluator still returned a placeholder `UpToDate`
  assessment even though the real TCB-info evaluation backend was not present.
- `TcbEvaluator::evaluate(...)` now fails closed with an explicit
  `IntelDcap("SGX TCB evaluation backend is not implemented")` error instead
  of constructing a synthetic TCB level that could be mistaken for a real
  platform state assessment.
- Added a focused regression in
  `services/tee-worker/nitro-sdk/src/attestation/intel_sgx.rs` covering the
  fail-closed TCB evaluation path under the `attestation-evidence` feature.

### 3zt. Nitro remote client auth alignment

- Tightened `x/verify/tee/nitro.go` and
  `services/tee-worker/l1-verifier/nitro.go`, where the remaining Nitro remote
  executor and remote attestation-verifier clients still issued unauthenticated
  requests even after the TEE worker control plane moved to loopback-or-bearer
  enforcement.
- Both Nitro clients now carry an explicit `APIToken` configuration, default it
  from `AETHELRED_TEE_API_TOKEN`, and attach that bearer token on remote
  `/execute` and `/verify` calls when configured.
- Added focused regressions in `x/verify/tee/nitro_test.go` and
  `services/tee-worker/l1-verifier/nitro_test.go` proving the authenticated
  remote executor and verifier paths succeed against a protected local test
  server.

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
- `cargo test --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features full-sdk lib_full::sovereign::`
- `cargo test --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features full-sdk zktensor`
- `cargo check --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features full-sdk`
- `cargo test -p aethelred-mempool`
- `cargo test -p aethelred-vm job_registry`
- `cargo test -p aethelred-vm precompiles::tee::tests`
- `go test ./x/verify/keeper/...`
- `go test ./x/verify/...`
- `go test ./x/validator/keeper`
- `go test ./x/pouw/keeper`
- `go test ./x/seal/keeper`
- `go test ./x/vault/keeper`
- `go test ./app -run 'Test(TeeModeRequiresHealthyVerifier|SafeInitTEEClient_.*|NewApp_NoPanic)$'`
- `go test ./app`
- `go test ./x/verify/tee ./services/tee-worker/l1-verifier`
- `go test ./x/seal/keeper`
- `go test ./app -run 'TestVerifyVoteExtensionHandlerRejects(MismatchedValidatorAddress|MismatchedHeight)$'`
- `go test ./x/pouw/keeper -run 'Test(UpdateParams|CB7_UpdateParams|ParamChangeProposal|Mainnet)'`
- `go test ./x/pouw/keeper -run 'Test(EvaluateVerificationPolicy|AuditChecklist|FullSecurityComplianceFlow|SecurityComplianceWithCorruptedState)'`

### Solidity / Hardhat / Foundry

- `npx hardhat compile`
- `npx hardhat size-contracts`
- `npx hardhat test` -> `61 passing`
- `forge test --match-path test/AethelredBridge.t.sol` -> `99 passed`
- `forge test --match-path test/AethelredVesting.t.sol` -> `104 passed`
- `forge test --match-path test/Cruzible.t.sol` -> `188 passed`
- `forge test --match-path test/CruzibleInvariant.t.sol` -> `13 passed`
- `forge test --match-path test/VaultInvariant.t.sol` -> `14 passed`
- `npx hardhat test test/institutional.reserve.automation.keeper.test.ts` -> `3 passing`
- `npx hardhat test test/deployment.governance.config.test.ts test/institutional.reserve.automation.keeper.test.ts` -> `9 passing`
- `go test ./x/seal/keeper/...` -> `ok`

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
- The active mempool signature middleware no longer admits transactions based
  on hybrid signature shape alone; it now performs real hybrid verification and
  sender binding against the serialized signed transaction body.
- The VM job registry now treats TEE and zk precompile failures as hard
  failures on mainnet/testnet config paths instead of silently downgrading to a
  structural-only acceptance path outside devnet.
- The live VM TEE precompile registry is now secure-by-default: mainnet-style
  runtime registration uses hardened enterprise TEE configs, while the old
  structural-only and placeholder platform paths are isolated behind explicit
  devnet-only construction helpers instead of being reachable through runtime
  defaults.
- The keeper’s simulated zk verification lane no longer treats proof length as
  a sufficient stand-in for verification. Even in dev/test mode, simulated
  proofs are now bound to their verifying key and public inputs so tampering
  produces deterministic failure instead of silent success.
- The worker sovereign-data path now uses real owner-bound authenticated
  encryption for protected/private/secret payloads instead of storing plaintext
  bytes behind encrypted-looking metadata. Ownerless access fails closed for
  encrypted payloads, required access reasons are enforced, UAE sovereign
  defaults now require a TEE privacy level, and private data rejects debug-mode
  or unacceptable-TCB enclave reports.
- The validator slashing keeper no longer records reputation-only or
  tombstone-only penalties as if they were full slashes when a staking keeper
  is present. It now applies real staking slash/jail hooks first and aborts
  cleanly if the economic penalty path cannot be resolved.
- The seal revocation manager no longer treats request IDs as sufficient
  authority to approve or execute revocation. Requests now have real lifecycle
  state, authority-threshold enforcement, dispute blocking, and fail-closed
  execution semantics.
- The safe app-initialization path no longer treats real remote TEE modes as
  degradable startup failures. If a deployment is configured for a real TEE
  verifier path, initialization now fails closed unless that path can be
  constructed successfully.
- The simulated Nitro app client no longer masquerades as real `aws-nitro`
  while emitting artifacts that violate the app's own schema and proof rules.
  It now carries an explicit simulated platform identity and stays aligned with
  the orchestrator's simulated wiring path.
- Nitro payload protection no longer uses base64-as-encryption in the verifier
  packages. Simulated Nitro now uses authenticated encryption, while remote
  Nitro encryption fails closed until a real attested enclave key path exists.
- Seal verification no longer equates signature presence with cryptographic
  verification. Signed attestations now require an explicit verifier backend or
  an opt-in insecure local fallback path.
- Seal export provenance no longer depends on an unenforced boolean option.
  Signed exports now require a real signer backend, and signing requests fail
  closed instead of silently producing unsigned exports.
- PQC startup availability checks no longer claim backend readiness
  unconditionally. Production and hybrid requests now reflect actual backend
  availability instead of a placeholder success signal.
- Enhanced seal verification no longer ignores envelope signatures when they
  are present. Signed enhanced bundles now require an explicit verifier backend
  or an opt-in insecure local fallback path.
- Imported seal exports no longer trust encoded payloads blindly. Content hashes
  are re-checked on import, and signed exports now require an explicit
  signature-verifier backend before they are accepted.
- TEE platform validation is now consistent across the app signer/verifier layer
  and the PoUW keeper. `nitro-simulated` and `mock-tee` are treated as
  simulated-only aliases instead of unknown or accidentally looser cases.
- The ABCI vote-extension ingress path now binds the embedded vote-extension
  identity to the authoritative consensus request earlier, so validator-address
  or height drift is rejected before staking lookup and signature verification
  rather than relying on later keeper-side aggregation checks.
- The PoUW mainnet lock registry is now enforced by the live `UpdateParams`
  execution path instead of existing only as advisory policy metadata. Locked
  governance fields fail closed at runtime unless and until a separately
  attestable elevated-governance override path exists.
- The PoUW audit-facing compliance and checklist surfaces now verify that
  runtime lock enforcement is actually present instead of inferring governance
  safety from the existence of registry metadata alone.
- Privileged trusted-measurement mutations now emit explicit
  `trusted_tee_measurement_registry_updated` events and structured audit-log
  records that distinguish fresh registrations, legacy Nitro index
  reconciliation, full revocations, and absent-measurement failures instead of
  leaving authority-level trust-root changes ambiguous in the runtime trail.
- Emergency trusted-measurement revocation no longer degrades to a
  single-member kill switch. The runtime now persists approval state, requires
  two bonded committee approvals for execution, and refuses to operate when
  the committee cannot satisfy that quorum safely.
- Seal revocation no longer lets ordinary privileged authorities or module
  authority bypass the governed dispute/approval path through direct helper or
  direct message shortcuts. The default privileged threshold is now multi-party
  and the emergency path is isolated as an explicit exception with mandatory
  justification on both single-seal and batch forced revocation entrypoints.
- That emergency seal exception no longer degrades to a single-signer kill
  switch. It now requires multi-party emergency approval, is limited to
  explicitly urgent reasons, and fails closed until the break-glass quorum is
  met.
- The vault keeper no longer leaves governance-only TEE and relay management
  methods protected only by documentation. Those state-mutating keeper entry
  points now enforce module authority directly at the boundary.
- The vault attestation-relay liveness path no longer relies on the phrase
  “governance-issued challenge” as a comment-level promise. Challenge issuance
  is now authority-gated, live challenges cannot be silently overwritten,
  expired challenge state rolls forward cleanly, and successful challenge
  issuance / response are recorded in the runtime audit trail.
- The `/admin/consensus/evidence/audit` route no longer behaves like an
  unauthenticated remote admin surface. It is now loopback-only by default,
  supports explicit bearer-token authorization for deliberate remote exposure,
  and rejects oversized request bodies before they reach the JSON decoder.
- The health endpoint no longer reports simulated or fallback-tolerated
  verification states as fully `healthy`. Overall health now distinguishes
  `simulated`, `degraded`, and `unhealthy` states more honestly, with `503`
  reserved for genuinely unhealthy runtime posture.
- The health endpoint no longer doubles as a remote information-disclosure
  surface for chain metadata, verifier readiness internals, and TEE capability
  details. Public callers get honest health state, while detailed diagnostics
  are now restricted to loopback or explicit token authorization.
- The metrics endpoint no longer behaves like a casually public operational
  surface. It now enforces its own `GET`-only boundary, defaults to loopback
  access, and requires explicit bearer-token authorization for deliberate
  remote scraping.
- The shared operational-route guard no longer grants unauthenticated access to
  proxied loopback traffic. Requests carrying forwarding headers must now use
  explicit bearer-token authorization before they can reach detailed health,
  metrics, or admin consensus-audit surfaces.
- The remote TEE client no longer treats endpoint safety as an execution-only
  concern. Unsafe or malformed remote endpoints are now rejected during client
  construction, and the health-probe path no longer bypasses the same SSRF
  guard used by execution and capability fetches.
- The verify-module readiness sweep no longer bypasses those same network
  safety rules during startup. Configured verifier targets now have to pass
  the shared endpoint validator before the node will probe them for
  reachability.
- The EZKL remote prover/verifier path no longer bypasses that validator
  either. Configured prover endpoints now have to pass the shared endpoint
  safety guard before `/prove` or `/verify` requests are issued.
- The DCAP verifier no longer treats PCCS and CRL collateral fetches as trusted
  by URL construction alone. Collateral and revocation endpoints now have to
  pass the same shared endpoint safety validator before any outbound request is
  issued from either the chain-side verifier or the mirrored worker copy.
- The mirrored worker Nitro service no longer lags behind the chain-side Nitro
  verifier on remote endpoint safety. Its remote executor and attestation
  verifier paths now fail closed on unsafe endpoints and bound remote error
  bodies with the same shared HTTP safety utilities.
- The consensus drand pulse provider no longer treats relay configuration as a
  trusted string. Relay endpoints now have to satisfy the shared endpoint
  safety contract, and the localhost fallback no longer decodes unbounded JSON
  bodies.
- The worker executor no longer treats its configured backend URL as implicitly
  safe. Both startup and request-time proxying now fail closed on unsafe
  backend targets instead of forwarding execution and attestation verification
  traffic by convention.
- The lightweight worker attestation engine no longer fabricates empty Intel or
  AMD collateral bundles that could be mistaken for partial verification state.
  Those collateral paths now fail closed until a real fetch backend is wired
  into that engine surface.
- The Nitro attestation wrapper no longer fabricates a placeholder parsed
  document after only recognizing a COSE shell. Nitro parsing now stops
  immediately with an explicit backend-unavailable error until a real CBOR/COSE
  parser is wired in.
- The ARM attestation wrapper no longer fabricates placeholder token state or
  report success from signature-verification methods that lack real crypto
  backends. Its parser and signature paths now fail closed explicitly.
- The shared endpoint validator now blocks literal loopback and non-routable
  IP forms centrally instead of relying on DNS resolution to catch those
  inputs after the fact, which closes an SSRF-style bypass class across the
  app, verify, and worker startup paths that reuse that helper.
- The TEE worker control plane no longer relies only on topology for safety.
  Non-loopback exposure now requires an explicit API token, the worker enforces
  loopback-or-bearer access on its HTTP routes, and the remote Go client
  participates in that contract by attaching the configured bearer token.
- The SGX attestation path no longer emits a placeholder `UpToDate` TCB result
  when there is no TCB evaluation backend. That assessment now fails closed
  explicitly instead of overstating platform trust.
- The remaining Nitro remote clients now participate in the same worker auth
  contract as the app-facing remote client, which closes an integration drift
  where the worker had been hardened but verifier-side callers had not yet
  started presenting the configured bearer token.
- The built-in security audit and threat model now describe the same hardened
  governance posture the runtime enforces, which removes an internal
  claim-vs-control mismatch around consensus threshold policy, one-way
  simulation gating, and app-layer vote-extension signing.
- The mirrored public SDK sovereign module has not yet been brought to the same
  owner-bound encryption contract in this tranche. The worker/runtime path is
  now the hardened source of truth; the public SDK mirror should be aligned in
  a follow-on pass rather than left to drift indefinitely.
- The mirrored public SDK source was updated to match the hardened hybrid
  signer/verifier path and the fail-closed `zktensor` contract, but
  `cargo test --manifest-path sdk/aethelred-sdk/Cargo.toml
  --features full-sdk --lib hybrid` still fails because of pre-existing
  full-SDK crate drift outside this change set (missing dependencies/stubs,
  `lib_full.rs` doc-comment layout issues, and unrelated serde coverage gaps).
