# Aethelred Infinity Sandbox — Enterprise API (v0.2.0)

This guide is the customer-facing reference for v0.2.0 of the Aethelred
Infinity Sandbox. It covers everything you need to integrate, run pilots,
verify seals independently, export audit trails, and wire the sandbox into
SOC / SIEM platforms.

> **Five-minute mental model**: A `Sandbox` is the producer side. It seals
> AI events into tamper-evident `DigitalSeal` objects. A `Verifier` is the
> reviewer side — anyone can re-verify a seal months later with no
> sector-specific code, no policy engine, just the seal + Merkle root.

## Crate map

| Crate                               | Purpose                                          |
| ----------------------------------- | ------------------------------------------------ |
| `aethelred-sandbox-core`            | Foundation: seal, evidence log, verifier, audit  |
| `aethelred-sandbox-finance`         | Credit, AML, trading, advisory                   |
| `aethelred-sandbox-healthcare`      | Genomics, clinical AI, ambient, claims           |
| `aethelred-sandbox-defense`         | Logistics, fusion, inspection, cyber + air-gap   |
| `aethelred-sandbox-supply-chain`    | Batch, customs, carbon, methane (CBAM, 45V)      |
| `aethelred-sandbox-ai-agents`       | Agent passport, tools, actions, prompt-injection |
| `aethelred-sandbox-autonomous-mobility` | ODD, mission, perception, safety case        |
| `aethelred-sandbox-research`        | Experiments, model release, repro, training      |

## Three lines of integration

```rust
use aethelred_sandbox_finance::prelude::*;

let sb = FinanceSandbox::quickstart("FAB")?;
let seal = sb.seal_credit_decision(CreditDecision::demo())?;
println!("Sealed: {}", seal.id_string());
```

That's it. The seal is in the evidence log, has a Merkle proof, and is ready
for export.

## Bulk seal API (5-minute pilot)

```rust
let sb = FinanceSandbox::quickstart("FAB")?;

// Seal 1000 credit decisions in one call.
let envs: Vec<SealEnvelope> = sb.append_and_envelope_batch(decisions)?;
// Every envelope shares the *final* Merkle root — single anchor.

let root = sb.current_root()?;
let bundle = sb.export_evidence()?;
```

Every sector exposes equivalent typed methods:

```rust
sb.seal_credit_decisions(...)      // finance
sb.seal_genomics_batch(...)        // healthcare
sb.seal_autonomous_logistics_batch(...)  // defense
sb.seal_batch_events(...)          // supply chain
sb.seal_passports(...)             // ai-agents
sb.seal_odd_validations(...)       // autonomous mobility
sb.seal_experiment_runs(...)       // research
```

## Reviewer-side independent verification

```rust
use aethelred_sandbox_core::prelude::*;

// Reviewer / auditor / regulator side. Only depends on sandbox-core,
// no sector crates needed.
let v = Verifier::default();
let report = v.verify_envelope(&envelope, expected_root)?;
assert!(report.passed());

// Strict posture for production-anchored seals.
let strict = Verifier::strict()       // require all artefacts
    .require_signature(true)
    .require_attestation(true)
    .require_zk_proof(true);
let report = strict.verify_envelope(&envelope, expected_root)?;
```

The verifier checks:

1. Schema version is supported.
2. Tamper-evidence — leaf hash matches seal, proof reconstructs root.
3. Field invariants — non-zero hashes, present tenant id / workflow id.
4. Validator signature parses (when present).
5. Attestation runtime nonce non-zero (when present).
6. zkML circuit hash non-zero (when present).
7. Optional: signature / attestation / zkML required for `strict()`.

## Audit trail (three formats)

```rust
let txt = sb.audit_trail(AuditFormat::PlainText)?;
let md  = sb.audit_trail(AuditFormat::Markdown)?;
let csv = sb.audit_trail(AuditFormat::Csv)?;

// Or build a structured AuditTrail for programmatic processing.
let trail: AuditTrail = sb.audit_trail_struct()?;
```

Markdown output drops cleanly into Confluence / Notion. CSV output drops
into SOC2 / SOX paperwork.

## Machine-readable error codes (SIEM / SOC)

Every `SandboxError` maps to a stable `SBX-<CATEGORY>-<NUMBER>` code:

```rust
match err.error_code().category {
    ErrorCategory::Policy => alert_compliance(),
    ErrorCategory::DataBoundary => alert_dlp(),
    ErrorCategory::Attestation => alert_security(),
    _ => log(err),
}
```

Codes are **stable** across versions. Examples:

| Code            | Meaning                                       |
| --------------- | --------------------------------------------- |
| `SBX-POL-1000`  | Generic policy denial                         |
| `SBX-POL-1001`  | Required gate failed                          |
| `SBX-DBN-3001`  | PII marker detected                           |
| `SBX-DBN-3002`  | PHI marker detected                           |
| `SBX-DBN-3003`  | Classified marker detected                    |
| `SBX-EVD-4002`  | Merkle proof verification failed              |
| `SBX-ATT-7001`  | Attestation runtime nonce was zero            |
| `SBX-ZKM-8001`  | zkML proof verification failed                |

The full catalog is in `aethelred_sandbox_core::error_code`.

## Async API

Enable the `async` feature:

```toml
aethelred-sandbox-core = { version = "0.2", features = ["async"] }
```

```rust
use aethelred_sandbox_core::async_api::SandboxAsync;

let entries = sb.append_seals_async(seals).await?;
let envs    = sb.append_and_envelope_batch_async(seals).await?;
let bundle  = sb.export_evidence_async().await?;
let trail   = sb.audit_trail_async(AuditFormat::Markdown).await?;
```

Large batches (≥16) automatically run on `spawn_blocking` to keep the async
runtime responsive.

## JSON Schema export (SDK code-gen)

Enable the `schema` feature:

```toml
aethelred-sandbox-core = { version = "0.2", features = ["schema"] }
```

```rust
use aethelred_sandbox_core::schema::SchemaBundle;

let bundle = SchemaBundle::generate();
std::fs::write("digital_seal.schema.json",
    serde_json::to_string_pretty(&bundle.digital_seal)?)?;
```

Schemas are JSON Schema Draft 7 — supported by every major SDK code-gen
tool (`quicktype`, `json-schema-codegen`, OpenAPI Generator, etc.).

## Property-based test fixtures

Sector crates ship `Fixtures` libraries with happy / regulatory-edge /
adversarial scenarios:

```rust
let sb = FinanceSandbox::quickstart("FAB")?;
for fix in FinanceFixtures::happy_path() {
    fix.run(&sb)?;
}
for fix in FinanceFixtures::adversarial() {
    fix.run(&sb)?;  // returns Ok if the sandbox blocks the bad input
}
```

Use these to drive your own integration tests. Each fixture has a stable
id and regulator tags so SIEM rules can key on them.

## Test counts (v0.2.0)

| Crate                                | Tests |
| ------------------------------------ | ----- |
| `sandbox-core` (incl. all features)  | 124   |
| `sandbox-finance`                    | 117   |
| `sandbox-healthcare`                 | 104   |
| `sandbox-defense`                    | 101   |
| `sandbox-supply-chain`               | 102   |
| `sandbox-ai-agents`                  | 100   |
| `sandbox-autonomous-mobility`        | 101   |
| `sandbox-research`                   | 103   |
| **Total**                            | **852** |

Every crate is 100+ tests, including unit, integration, and proptest.

## Production-deployment checklist

- [ ] Enable `real-crypto` (default) — uses workspace `aethelred-core` primitives.
- [ ] Provision validator-quorum keys (`SandboxBuilder::validator_keys_provisioned(true)`).
- [ ] Disable mock attestation (`SandboxBuilder::disable_mock_attestation()`).
- [ ] Wire a real attestation verifier for your TEE platform.
- [ ] Wire a real zkML proof generator for high-stake seals.
- [ ] Set `Verifier::strict()` for reviewer-side checks.
- [ ] Anchor evidence Merkle root to mainnet.
- [ ] Map error codes to SOC / SIEM rules using `error_code::*`.

## Per-sector reference

See each sector crate's README:

- `sandbox-finance/README.md` — workflows, regulator citations, FIX / FpML / ISO 20022 / SWIFT.
- `sandbox-healthcare/README.md` — DoH / DHA / MOHAP / EHS / HIPAA / EU AI Act.
- `sandbox-defense/README.md` — Tawazun / NATO PRU / DoD AI EP / ITAR / EU dual-use, air-gap mode.
- `sandbox-supply-chain/README.md` — CBAM / 45V / 45Q / methane / EPCIS.
- `sandbox-ai-agents/README.md` — EU AI Act Art 26 / ISO 42001 / NIST AI RMF / UAE PDPL.
- `sandbox-autonomous-mobility/README.md` — ISO 21448 / 26262 / DO-178C / DO-326A / DO-356A.
- `sandbox-research/README.md` — FAIR / NeurIPS / MLPerf / ISO 42001 / NIST AI RMF / UNESCO.
