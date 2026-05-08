# Aethelred Infinity Sandbox

> Production-grade sovereign AI risk simulator and evidence layer.
> Seven plug-and-play sector crates built on a shared cryptographic foundation.

---

## What this is

The Aethelred Infinity Sandbox is **seven production-grade sector sandboxes** that each let an enterprise AI deployment seal AI events with portable, regulator-readable, tamper-evident evidence — without moving regulated data and without requiring weeks of integration.

Each sandbox produces a canonical `DigitalSeal` — a cryptographically signed evidence object that binds together the model, the input policy class, the execution environment (TEE attestation), the human approvals, and the output. The same seal schema is readable by any reviewer in any jurisdiction.

The seven sectors are individually consumable as separate crates. A customer pulls only what they need.

| Sector | Crate | Workflows |
|---|---|---|
| **Finance** | `aethelred-sandbox-finance` | Credit decisions, AML/sanctions screening, trading events, advisory recommendations |
| **Healthcare** | `aethelred-sandbox-healthcare` | Genomics inference, clinical AI, ambient scribe, claims adjudication |
| **Defense** | `aethelred-sandbox-defense` | Autonomous logistics, sensor fusion, inspection QA, cyber defense (with air-gap) |
| **Supply Chain** | `aethelred-sandbox-supply-chain` | Batch traceability, customs filing, carbon claims, methane events |
| **AI Agents** | `aethelred-sandbox-ai-agents` | Agent passport, tool invocation, action trail, prompt-injection defense |
| **Autonomous Mobility** | `aethelred-sandbox-autonomous-mobility` | ODD validation, mission step replay, perception events, safety case |
| **Research** | `aethelred-sandbox-research` | Experiment runs, model release, reproducibility checks, training-run lineage |

---

## Plug-and-play in 3 lines

Each sector exposes the same API shape — one constructor, typed `seal_*` methods.

### Finance (FAB / EDB / Khalifa Fund)
```rust
use aethelred_sandbox_finance::prelude::*;

let sandbox = FinanceSandbox::quickstart("FAB")?;
let seal = sandbox.seal_credit_decision(CreditDecision::demo())?;
println!("Sealed: {}", seal.id_string());
```

### Healthcare (M42 / PureHealth / Globalpharma)
```rust
use aethelred_sandbox_healthcare::prelude::*;

let sandbox = HealthcareSandbox::quickstart("M42")?;
let seal = sandbox.seal_genomics_inference(GenomicsInference::demo())?;
```

### Defense (EDGE / Tawazun / TII)
```rust
use aethelred_sandbox_defense::prelude::*;

let sandbox = DefenseSandbox::quickstart("EDGE")?;  // air-gap on by default
let seal = sandbox.seal_autonomous_logistics(AutonomousLogistics::demo())?;
```

### Supply Chain (KEZAD / ADNOC / Masdar)
```rust
use aethelred_sandbox_supply_chain::prelude::*;

let sandbox = SupplyChainSandbox::quickstart("KEZAD")?;
let seal = sandbox.seal_batch_event(BatchEvent::demo())?;
```

### AI Agents (Core42 / Presight)
```rust
use aethelred_sandbox_ai_agents::prelude::*;

let sandbox = AiAgentsSandbox::quickstart("Core42")?;
sandbox.seal_passport(AgentPassport::demo())?;
sandbox.seal_tool_invocation(ToolInvocation::demo())?;
```

### Autonomous Mobility (TII VentureOne / EDGE / KU)
```rust
use aethelred_sandbox_autonomous_mobility::prelude::*;

let sandbox = AutonomousMobilitySandbox::quickstart("TII")?;
let seal = sandbox.seal_mission_step(MissionStep::demo())?;
```

### Research (MBZUAI / Khalifa University / TII)
```rust
use aethelred_sandbox_research::prelude::*;

let sandbox = ResearchSandbox::quickstart("MBZUAI")?;
let seal = sandbox.seal_experiment_run(ExperimentRun::demo())?;
```

---

## Architecture

```
                         ┌────────────────────────────────────┐
                         │   Customer code (one of seven      │
                         │   sector preludes)                 │
                         └────────────────┬───────────────────┘
                                          │ typed seal_*() methods
                ┌─────────────────────────┴─────────────────────────┐
                │                                                   │
   ┌────────────▼────────────┐                       ┌──────────────▼────────────┐
   │ aethelred-sandbox-finance│   ... 6 more sector  │ aethelred-sandbox-research │
   │   • CreditDecision       │       crates ...     │   • ExperimentRun           │
   │   • AmlAlert             │                      │   • ModelReleasePack        │
   │   • TradingEvent         │                      │   • ReproducibilityCheck    │
   │   • Advisory             │                      │   • TrainingRun             │
   │   + 7 regulator views    │                      │   + 7 framework views       │
   │   + FIX / FpML / ISO 20022│                     │   + MLflow / W&B / RO-Crate │
   └────────────┬─────────────┘                      └──────────────┬──────────────┘
                │                                                   │
                └────────────────────┐         ┌────────────────────┘
                                     │         │
                       ┌─────────────▼─────────▼─────────────┐
                       │    aethelred-sandbox-core           │
                       │   (foundation — workflow engine,    │
                       │    DigitalSeal v1, EvidenceLog,     │
                       │    PolicyEngine, TEE, zkML)         │
                       └─────────────────┬───────────────────┘
                                         │ workspace dep
                                         │
                       ┌─────────────────▼───────────────────┐
                       │    aethelred-core::crypto           │
                       │   (real SHA-256, RFC 9162 Merkle,   │
                       │    ECDSA P-256 + Dilithium-3 hybrid)│
                       └─────────────────────────────────────┘
```

### Why workspace crypto?

Sandbox seals use the **same cryptographic primitives** as the mainnet protocol — `aethelred-core::crypto::{sha256, merkle_combine, merkle_root, HybridKeyPair, HybridSignature}`. A seal produced in a sandbox is **byte-for-byte indistinguishable** from a seal produced by a validator. There is no "sandbox crypto" / "real crypto" divergence.

### Why typed sector APIs?

Each sector exposes a typed input struct (e.g., `CreditDecision`, `GenomicsInference`, `AutonomousLogistics`). This means:

- **Compile-time safety**: a customer cannot accidentally pass a healthcare input to a finance method.
- **Builder ergonomics**: every input has a `::builder()` and a `::demo()`. Demos let you copy-paste running code in 30 seconds.
- **No reflection / runtime polymorphism**: the type system enforces the right shape. If your code compiles, the input shape matches the sector.

---

## Foundation (`aethelred-sandbox-core`)

Every sector uses these shared primitives:

| Type | What it does |
|---|---|
| `DigitalSeal` | The canonical AI-event evidence object (v1). Includes `model_hash`, `policy_id`, `input_hash`, `output_hash`, `approvals`, `attestation`, `zk_proof`, `validator_signature_hex`, `sector_extension`. |
| `Hasher::sha256` / `merkle_root` | Real SHA-256 + RFC 9162-compatible Merkle (via workspace crypto). |
| `EvidenceLog` | Tamper-evident, append-only seal log with per-entry Merkle inclusion proofs. |
| `PolicyEngine` | Fail-closed policy gating. Required gates dominate optional gates. |
| `TeePlatform` / `Attestation` | Intel TDX / AMD SEV-SNP / AWS Nitro / NVIDIA H100 / ARM CCA / Azure CC / GCP Confidential Space. |
| `ProofSystem` / `ProofArtefact` | EZKL / RISC Zero / Modulus Remainder / Plonky2 / Groth16 with selection heuristic. |
| `Sandbox::builder()` | Generic builder for any sector to compose policy + workflows + tenant identity. |

---

## Plug-and-play three-tier escape hatches

Every sector supports three integration tiers:

1. **Quickstart** (one line):
   ```rust
   FinanceSandbox::quickstart("FAB")
   ```

2. **Builder** (declarative):
   ```rust
   FinanceSandbox::builder()
       .institution("FAB")
       .jurisdiction(FinanceJurisdiction::Cbuae)
       .max_amount(rust_decimal::Decimal::new(1_000_000_000, 0))
       .with_extra_gate(custom_gate)
       .build()?
   ```

3. **Direct construction** (full control via `aethelred-sandbox-core::Sandbox::builder`).

---

## Adversarial / fail-closed semantics

Every sector includes adversarial tests baked into the unit-test suite. Examples:

- **Finance**: negative credit amount → `FailClosed`; PII marker (`@`, `ssn:`, `emirates_id:`) in pseudo-id → `FailClosed`; trading risk-limit exceeded → `FailClosed`.
- **Healthcare**: PHI marker in pseudo-id → `FailClosed`; unsigned ambient note → `FailClosed`; adverse claim without reason class → `FailClosed`.
- **Defense**: classified marker (`TS//SCI`, `SECRET//`) → `FailClosed`; non-weaponised scope flag absent → `FailClosed`.
- **AI Agents**: tool not in manifest → `FailClosed`; privileged action without approval → `FailClosed`; prompt-injection rejected → seal fails closed if the agent did NOT reject the injection.
- **Research**: restricted dataset → `FailClosed`; missing code commit → `FailClosed`.

These properties are guaranteed by the policy engine: required-gate failures dominate optional-gate failures.

---

## Regulator-shape views

Every seal can be projected into a jurisdiction-specific view that bundles the appropriate regulator citations.

| Sector | Supported regulator views |
|---|---|
| Finance | CBUAE, SCA, FSRA, DFSA, FCA UK, OCC/Fed/FinCEN US, MAS |
| Healthcare | DoH Abu Dhabi, DHA, MOHAP, EHS, HIPAA, EU AI Act + GDPR, NHRA |
| Defense | Tawazun, UAE AF, NATO PRU, US DoD AIEP, UK MoD, ITAR, EU Dual-Use |
| Supply Chain | EU CBAM, EU Methane Reg, US 45V, US 45Q, EU CSRD/ISSB, UAE EAD/Customs, WCO SAFE |
| AI Agents | EU AI Act Art 26, ISO/IEC 42001, NIST AI RMF, UAE PDPL, UAE NAIP |
| Autonomous Mobility | ISO 21448 SOTIF, ISO 26262, DO-178C, DO-326A, DO-356A, EU/UNECE WP.29, UAE NCEMA/RTA |
| Research | FAIR principles, NeurIPS reproducibility, MLPerf, ISO/IEC 42001, NIST AI RMF, UNESCO AI Ethics, EU AI Act research |

---

## Test coverage

```
sandbox-core                 28 tests
sandbox-finance              28 tests (24 unit + 4 integration)
sandbox-healthcare           17 tests
sandbox-defense              8 tests
sandbox-supply-chain         7 tests
sandbox-ai-agents            9 tests
sandbox-autonomous-mobility  6 tests
sandbox-research             7 tests
─────────────────────────────────────────
TOTAL                       110 unit/integration tests, 0 failures
```

Plus doctest examples that compile and the umbrella `aethelred-sandbox` crate with the `infinity` feature flag for one-dependency access to all seven sectors.

---

## Workspace layout

```
crates/
├── sandbox-core/                       # foundation
├── sandbox-finance/
├── sandbox-healthcare/
├── sandbox-defense/
├── sandbox-supply-chain/
├── sandbox-ai-agents/
├── sandbox-autonomous-mobility/
├── sandbox-research/
└── sandbox/                            # legacy v0.1 + `infinity` umbrella feature
```

To use everything from one dependency:

```toml
[dependencies]
aethelred-sandbox = { path = "../crates/sandbox", features = ["infinity"] }
```

Then:

```rust
use aethelred_sandbox::infinity::finance::prelude::*;
```

To use only one sector (recommended for production):

```toml
[dependencies]
aethelred-sandbox-finance = { path = "../crates/sandbox-finance" }
```

---

## What we deliberately did not build

- **A new cryptographic library**. We use `aethelred-core::crypto` exclusively.
- **Sector connectors that need the source-of-record system to be online**. Connectors are stubbed via `aethelred-sandbox-core::Connector`; concrete connectors live outside this crate (where the customer's network connectivity is available).
- **Production validator-quorum signing**. The seal carries an `Option<String>` for the hybrid signature; production deployments plug in the real validator quorum via `aethelred-core`.
- **Live attestation verification**. The TEE module defines the receipt-side envelope; verifiers (Intel PCS / AMD KDS / AWS Nitro PKI / NVIDIA RIM) live in dedicated crates that wrap the platform PKI.

These are deliberate boundaries — each one is filled in by a separate, dedicated crate in the production deployment.

---

## License

Apache-2.0.
