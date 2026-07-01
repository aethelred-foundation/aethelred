# ADR-0003 — Confidential Execution & Attestation Protocol (CEAP)

**Status:** Proposed · **Date:** 2026-07-01 · Implements pillars 1+4 of
[ADR-0002](ADR-0002-moat-architecture.md). This is the protocol spine — the part
that is genuinely un-copyable and exactly what sovereign/regulated buyers need.

## The core idea: two orthogonal, independently-attested dimensions

Today `x/verify` has one axis — `VerificationType ∈ {TEE, ZKML, HYBRID}` — which
*conflates* "how was the data kept confidential" with "how was correctness
proven." A regulated client cares about **both, separately**:

- **Confidentiality backend** — *how was the data protected while it was
  computed on?* `NONE · TEE · FHE · MPC · HYBRID`
- **Verification method** — *how was correctness proven?*
  `NONE · ZKML · FREIVALDS · OPTIMISTIC · REEXEC · TEE_ATTESTED`

The product **{backend} × {verification}** is the capability surface. A bank's
crown-jewel workload can demand *FHE confidentiality* (no hardware trust) **and**
*zkML verification* (cryptographic correctness) — fully cryptographic, end to
end. A latency-sensitive workload can accept *TEE + TEE-attested*. **The network
records the exact cell used in the post-quantum Digital Seal**, so the regulator
reads precisely how the computation was protected *and* proven.

No competitor separates and attests these two axes with a single settlement
object. That separation is the moat's technical core.

## Protocol objects

### ConfidentialityPolicy (client-declared, network-enforced)
Attached to a compute job / contract call. The network must satisfy it or reject
the job — it is never silently downgraded.

```
ConfidentialityPolicy {
  allowed_backends      []Backend      // e.g. [FHE, MPC] — hardware trust forbidden
  min_verification      Verification   // e.g. ZKML
  allowed_platforms     []Platform     // e.g. [SEV_SNP, TDX] only
  require_vendor_root    bool           // no test roots — production silicon only
  data_residency        []Jurisdiction // allowed regions; data may not egress them
  disclosure            DisclosurePolicy // who may see what (drives ZK selective disclosure)
  policy_hash           bytes          // canonical hash, bound into the seal
}
```

### ConfidentialityAttestation (worker-produced, quorum-verified, seal-bound)
```
ConfidentialityAttestation {
  backend        Backend       // achieved
  verification   Verification  // achieved
  platform       Platform      // SEV_SNP / TDX / SGX / NITRO / GPU_CC / … (backend-specific)
  measurement    bytes         // launch/firmware measurement or FHE param/circuit hash
  trust_basis    TrustBasis    // vendor_root | test_root  (reuses internal/attestation)
  data_sealed    bool          // data was encrypted to the backend; operator had no plaintext
  policy_hash    bytes         // the policy this satisfies
  worker         string        // executing worker
  signature      bytes         // worker hybrid (secp256k1 + ML-DSA) signature over the above
}
```

The **Digital Seal gains this attestation** (seal proto extension), so the
seal — already PQC-quorum-signed — now testifies to *confidentiality + verification
+ jurisdiction*, not just an output commitment.

## Pluggable backend interface (Go)

Confidentiality is a **capability provided by a backend**, resolved at runtime by
a policy engine. Backends are first-class and swappable; adding FHE/MPC/GPU-CC
later is a new backend, not a protocol change.

```go
type ConfidentialBackend interface {
    Kind() Backend
    Available() error                       // honest capability probe (no faking)
    SatisfiesPlatform(Platform) bool
    Prepare(ctx, ConfidentialityPolicy) (Session, error)   // enclave / FHE keys / MPC session
    Execute(ctx, Session, EncryptedInput, ModelRef) (Output, ConfidentialityAttestation, error)
}
```

- **TEE backend** [HAVE] — wraps `internal/attestation` (SEV-SNP/TDX/SGX/Nitro)
  and the enclave executor. Production path.
- **FHE backend** [FRONTIER] — CKKS approximate inference for small models; its
  `Available()` returns "not yet operational" until wired, and it is *labelled*
  a research tier — never presented as production.
- **MPC backend** [BUILD] — threshold secret-sharing inference.
- **GPU-CC backend** [BUILD] — confidential-compute-mode GPUs for large models.
- **Hybrid** — e.g. FHE-encrypted input executed inside a TEE (defence in depth).

### Policy engine (deterministic, consensus-safe)
Given a `ConfidentialityPolicy`, select a backend that satisfies
`allowed_backends ∩ available ∩ platform ∩ residency`, deterministically (lowest
ordinal among satisfying backends), or **reject**. Validators do **not**
re-select — they verify the returned `ConfidentialityAttestation` against the
policy. This keeps consensus deterministic while execution is off-chain in the
backend.

## Sovereign / consortium deployment

A deployment pins, per instance: default policy, `allowed_backends`,
`allowed_platforms`, `require_vendor_root`, `data_residency`, and its own
validator set. The client runs the network **in its own jurisdiction**; raw data
never leaves the enclave/boundary — only commitments and seals are portable and
publishable to the public verification network. This is the sales moat on top of
the tech moat: a bank or ministry gets a sovereign instance whose every AI
decision carries a post-quantum, policy-bound, court-admissible seal.

## What ships in what order

1. **Foundation (done):** the Go `internal/confidential` package — `Backend`,
   `Verification`, `Platform`, `ConfidentialityPolicy` (+ `Satisfies`),
   `ConfidentialityAttestation`, the `ConfidentialBackend` interface, the policy
   engine, a TEE backend adapter over `internal/attestation`, and honest
   FHE/MPC/GPU-CC placeholders (`Available()` = not-yet-operational). 100% covered.
2. **Seal binding (done):** `DigitalSeal.confidentiality` (seal proto) and
   `ComputeJob.confidentiality_policy` / `MsgSubmitJob.confidentiality_policy`
   (pouw proto). The submitter's policy rides `submit-job` (`--conf-*` flags) onto
   the job; at completion `x/pouw/keeper/confidential.go` derives the achieved
   `ConfidentialityAttestation` from the consensus-agreed verification results and
   the chain's trust basis (`AllowSimulated` ⇒ test_root, else vendor_root),
   enforces `Satisfies` **before any state write** (a non-compliant job is never
   sealed), binds the attestation into the seal, and folds it into the
   tamper-evident seal ID (`GenerateID`). Deterministic — validators verify, never
   re-select. Covered by pure-unit + `CompleteJob` integration tests.
3. **Precompiles (done, pending EVM host):** `precompiles/seal` — `ISeal.sol` +
   embedded ABI + Go precompile at 0x0900 (0x0901 IVerify / 0x0902 IPoUW
   reserved). `getSeal`, `getConfidentiality`, `getSealIdByJob`, `verifySeal`,
   and `requireConfidentiality`, which evaluates a Solidity-supplied
   ConfidentialityPolicy with the SAME `internal/confidential.Satisfies` that
   consensus ran at sealing — bit-identical gating semantics, no oracle. ABI
   dispatch, gas schedule, and keeper-backed reads complete and tested against
   a real seal keeper; mounting into the EVM is the thin cosmos/evm adapter
   (ADR-0001 Phase 1) — the host extracts sdk.Context and calls Run.
4. **FHE/MPC/GPU-CC backends (engines done, honestly scoped):**
   - **FHE (real):** CKKS via Lattigo v6 — LogN 13, LogQP 161 ≤ the 128-bit
     bound for N=8192. Client keeps the secret key; the engine evaluates
     y = W·x + b on ciphertext (ct×pt multiply → rescale → rotation inner-sum)
     and provably cannot decrypt: DataSealed = true is cryptographic fact.
     Honest scope: linear/affine models (risk scores, logits). Verification =
     none (FHE proves confidentiality, not correctness). Malformed-ciphertext
     panics from the library are recovered into errors (adversarial input can
     never crash a worker).
   - **MPC (real protocol, deployment-aware claim):** n-of-n additive secret
     sharing over Z_2^64, fixed-point 2^16. Public model / secret input needs
     no Beaver triples for the linear class; parties compute on shares behind
     the MPCParty transport seam. The honesty gate: DataSealed = !Colocated —
     an in-process cluster runs the real protocol but claims NO secrecy, since
     one operator holds all shares. Only independent operators seal data.
   - **GPU-CC (real wiring, detection-gated):** Available() is driven by live
     NVIDIA confidential-compute detection (nvidia-smi conf-compute), never by
     configuration — the backend cannot be faked into availability. Executor +
     NRAS attestation lift complete; enabling it on an H100 CC host is a
     deployment step, not an engineering one.
   Config-less constructors (NewFHEBackend()/NewMPCBackend()/NewGPUCCBackend())
   remain honestly not-operational; the engine-backed constructors are the
   operational path.
5. **Worker wiring (done):** the verification orchestrator (x/verify) carries a
   confidential.Registry (SetConfidentialRegistry, assembled at the composition
   root from genuinely operational backends). ExecuteConfidential selects per
   policy (never downgrades), executes, binds the policy hash, and PRE-FLIGHTS
   the attestation with the same Satisfies check consensus runs — an honest
   worker never submits a result the chain must reject (e.g. a colocated MPC
   cluster against a data-sealing policy fails at the worker, not on-chain).
   WireSignalForBackend ↔ DeriveAttestation are inverse mappings, so the seal
   reports exactly the backend that ran ("fhe"/"mpc" wire signals now lift to
   BackendFHE/BackendMPC on-chain).
6. **EVM execution layer (done, internal/evmhost):** the real go-ethereum
   interpreter with ISeal mounted at 0x0900 — real contract bytecode gates on
   seal confidentiality end-to-end in tests. Full EVM *transaction* hosting
   (cosmos/evm) requires the SDK v0.53 upgrade (see ADR-0001 Phase 1 note).

## Honesty ledger
- Real now: the TEE backend, the policy model, the attestation seal binding,
  PQC signing, CKKS FHE for linear models, additive-sharing MPC (protocol),
  the ISeal precompile logic, GPU-CC detection + wiring.
- Deployment-gated: MPC confidentiality (requires non-colocated operators),
  GPU-CC availability (requires CC-mode silicon), ISeal on-chain exposure
  (requires the cosmos/evm host, ADR-0001 Phase 1).
- Frontier (labelled): FHE inference beyond the linear class at useful speed.
  The engine rejects models it cannot faithfully execute — we never claim
  depth we do not have.
