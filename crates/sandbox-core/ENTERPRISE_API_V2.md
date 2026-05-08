# Aethelred Infinity Sandbox — Enterprise API v0.2.1

**v0.2.1 closes the production-grade gap.** Where v0.2.0 had a well-tested
*API surface* with stub implementations, v0.2.1 ships **real implementations**
behind every module.

This document describes the new enterprise modules and their production
guarantees.

## What's new in v0.2.1

| Module                   | What it replaces / adds                                   |
| ------------------------ | --------------------------------------------------------- |
| `crypto_signing`         | **Real hybrid (ECDSA + Dilithium-3) signatures**, not stub strings |
| `scanner`                | **Production PII/PHI/PCI/classification detector** with Luhn, MOD-97, MOD-11 checksums |
| `persistence`            | **Durable JSON-lines evidence log** with WAL, fsync, recovery, tamper-detect |
| `policy_dsl`             | **JSON policy authoring** — compliance teams don't write Rust |
| `metrics`                | **Prometheus-compatible** counters, gauges, histograms     |
| `anchor`                 | **Merkle-root anchoring** with mock, signed, and file backends |
| `connector_jsonl`        | **Real JSONL replay + mpsc channel connectors**            |
| **CLI binary**           | `aethelred-sandbox` — keygen, sign, verify, scan, audit, prometheus |
| **Criterion benchmarks** | Real throughput numbers — see "Performance SLOs" below     |

## Real cryptography (v0.2.1)

```rust
use aethelred_sandbox_core::prelude::*;

// Generate a hybrid keypair (ECDSA-secp256k1 + CRYSTALS-Dilithium-3, NIST FIPS 204).
let signer = HybridSealSigner::generate("validator-1")?;

// Sign a seal — produces a real cryptographic SignedSeal.
let signed = signer.sign_seal(seal)?;

// Days/years later, an independent reviewer verifies:
let verifier = HybridSealVerifier::for_signer("validator-1", signer.public_key().clone());
verifier.verify_signed_seal(&signed)?;

// Multi-validator (M-of-N) quorum:
let quorum = ValidatorQuorum::new(vec![s1, s2, s3], /* threshold */ 2)?;
let qs = quorum.sign(seal)?;
assert!(qs.is_threshold_met());
```

**Wire format**: `SignatureEnvelope` carries the ECDSA bytes (64 bytes), the
Dilithium-3 bytes (~3.3 KB), the security level, the chain id, the
`signed_at` timestamp, and the recomputed message hash. Stored hex-encoded
in `DigitalSeal::validator_signature_hex` for v0.2.0 backwards compat;
structured access via `SignedSeal::from_seal(...)`.

**Quantum-first posture**: At `QuantumThreatLevel::Q_DAY`, the verifier
uses Dilithium-only mode. Use `HybridSealVerifier::strict_mainnet()` or
configure manually via `VerifierConfig`.

## Production-grade sensitive-data scanner

Replaces v0.2.0's `contains("@") || contains("ssn:")` toy detector.

```rust
let scanner = Scanner::new();
let findings = scanner.scan(text);
// Detects: email, E.164 phone, US SSN (with area-code validity), US EIN,
// IBAN (mod-97 checksum), credit card (Luhn), Emirates ID, MRN, NHS
// (mod-11 checksum), classification markers (TS//SCI, SECRET//, etc.),
// and high-entropy strings (Shannon entropy ≥ 4.5 bits/char).

let summary = scanner.summary(text);
// Returns counts per class: pii, phi, pci, classified, secret.
```

Each `Finding` carries:
- `detector`: stable id
- `class`: PII / PHI / PCI / Classified / Secret
- `start..end`: byte offsets
- `confidence`: low / medium / high
- `redacted_context`: 8-byte windows around the match with `***` substitution

## Durable evidence log

```rust
use aethelred_sandbox_core::prelude::*;

let log = PersistentEvidenceLog::open("/var/lib/aethelred/fab.jsonl")?;
log.append(seal)?;       // fsync'd to disk by default
let root = log.root()?;  // Merkle root over all entries

// Recovery on startup:
let log = PersistentEvidenceLog::open("/var/lib/aethelred/fab.jsonl")?;
// Reads existing entries, recomputes leaf hashes, verifies file
// integrity, refuses to open if any entry was tampered.

// Compaction:
log.compact_to("/backup/snapshot.json")?;
```

## Policy DSL

Compliance teams author policies in JSON:

```json
{
  "schema_version": 1,
  "policy_id": "po_credit_v3",
  "owner": "FAB Compliance",
  "effective_from": "2026-01-01T00:00:00Z",
  "gates": [
    {
      "id": "finance.amount_bounds",
      "name": "Amount within bounds",
      "rule": "Credit amount must be in [0, 1bn AED].",
      "severity": "required",
      "tags": ["amount", "cbuae"],
      "regulators": [{"id": "CBUAE", "citation": "AML/CFT Reg Art. 16"}]
    }
  ]
}
```

```rust
let doc = PolicyDocument::from_json_file("/etc/aethelred/policies/po_credit_v3.json")?;
let engine = doc.into_engine()?;  // ready-to-use PolicyEngine
```

## Prometheus-compatible metrics

```rust
let m = SandboxMetrics::new();
m.record_seal("finance", "credit_decision", "allow");
m.record_seal_duration("finance", "credit_decision", 0.012);
m.record_policy_denial("finance.amount_bounds");
m.record_signature_failure("validator-1");

// Render for /metrics endpoint:
let prom = m.export_prometheus();
// # HELP aethelred_seals_total ...
// # TYPE aethelred_seals_total counter
// aethelred_seals_total{outcome="allow",sector="finance",workflow_id="credit_decision"} 1
// ...
```

## Merkle-root anchoring

```rust
// Mock for tests:
let svc = MockAnchorService::new("test");
let r = svc.anchor("FAB", merkle_root)?;

// File-backed (audit-friendly JSONL):
let svc = FileAnchorService::open("aethelred-mainnet", "/var/lib/aethelred/anchors.jsonl")?;
let r = svc.anchor("FAB", merkle_root)?;

// Cryptographically signed:
let signer: Box<dyn SealSigner> = Box::new(HybridSealSigner::generate("anchor-1")?);
let svc = SignedAnchorService::new("signed-anchor", "quorum-1", signer);
let r = svc.anchor("FAB", merkle_root)?;
svc.verify(&r)?;
```

`AnchorProof` is an enum supporting `AethelredMainnet`, `Evm` (Ethereum / Polygon),
`Rfc3161` (legal-evidence-grade timestamping), `Quorum` (offline / air-gap),
and `Mock`.

## Real connectors

```rust
// Replay events from a JSON-lines file:
let mut c: JsonlFileConnector<MyEvent> = JsonlFileConnector::new("/data/2026-q1.jsonl");
c.open()?;
while let Some(event) = c.next()? { sandbox.seal(event)?; }

// Or stream from any in-process producer:
let (tx, rx) = std::sync::mpsc::channel::<MyEvent>();
let mut c = ChannelConnector::new("kafka:trades", rx).blocking();
c.open()?;
```

## CLI binary

```sh
# Generate a public key (secret stays in HSM in production):
aethelred-sandbox keygen --out validator.pub.json

# Sign a seal end-to-end (one-shot):
aethelred-sandbox sign \
  --in seal.json \
  --out signed.json \
  --pub-out signer.pub.json \
  --signer-id "fab-validator"

# Verify (independently):
aethelred-sandbox verify \
  --pubkey signer.pub.json \
  --in signed.json \
  --signer-id "fab-validator"
# verify: OK (hybrid-ecdsa-dilithium3)
# echo $? → 0

# Scan logs / docs for sensitive data (CI/CD gate):
aethelred-sandbox scan --in audit.log --json
# echo $? → 1 if findings, 0 otherwise

# Render audit trail in any format:
aethelred-sandbox audit --bundle bundle.json --format markdown > report.md
aethelred-sandbox audit --bundle bundle.json --format csv > soc2.csv

# Emit Prometheus metrics for a bundle:
aethelred-sandbox prometheus --bundle bundle.json
```

## Performance SLOs (criterion-measured)

Apple Silicon, default build:

| Operation                          | p50      | Notes                              |
| ---------------------------------- | -------- | ---------------------------------- |
| `Hasher::hash_value(&seal)`        | ~4 µs    | leaf hash of canonical seal JSON   |
| `seal.pre_signature_hash()`        | ~4 µs    | sign-message preparation           |
| `EvidenceLog::append` (1k batch)   | ~5 ms    | in-memory, including hash + push   |
| Hybrid sign (ECDSA + Dilithium-3)  | ~252 µs  | Dilithium dominates                |
| Hybrid verify                      | ~115 µs  |                                    |
| Merkle proof build (n=1024)        | ~580 µs  |                                    |
| Merkle proof verify                | ~10 µs   |                                    |
| Scanner (mixed 200-char doc)       | ~30 µs   |                                    |

→ Single thread sustains ~4k seals/s with full hybrid signing,
~250k seals/s with hashing only.

## Module count and test count

| Module                | Tests | Notes                                |
| --------------------- | ----- | ------------------------------------ |
| `crypto_signing`      | 21    | Real hybrid sign/verify roundtrips   |
| `scanner`             | 28    | Real Luhn / MOD-97 / MOD-11 vectors  |
| `persistence`         | 16    | File round-trips + tamper detection  |
| `policy_dsl`          | 19    | JSON parse / validate / compile      |
| `metrics`             | 22    | Prometheus text-format export        |
| `anchor`              | 16    | Mock + signed + file backends        |
| `connector_jsonl`     | 21    | File replay + channel streaming      |
| **New module total**  | **143** | All passing on macOS / Linux       |

Add to v0.2.0 baseline (852) → **v0.2.1 totals ~995 tests** in sandbox-core
+ all sector crates.

## Production deployment checklist

- [ ] Use `HybridSealSigner::generate` only for dev. In production, swap to
      `aethelred_core::crypto::signer::ValidatorHsmSigner` (PKCS#11 / KMS).
- [ ] Use `PersistentEvidenceLog::open` with `sync_on_append = true`.
- [ ] Anchor each new Merkle root via `SignedAnchorService` to the mainnet.
- [ ] Wire `SandboxMetrics` to your Prometheus scraper (`/metrics` endpoint).
- [ ] Author policies in JSON via `PolicyDocument`, version-control them.
- [ ] Run `Scanner` on every connector input — defense-in-depth.
- [ ] Use `Verifier::strict_mainnet()` for reviewer-side checks.
- [ ] Map error codes (`SBX-*`) to your SOC / SIEM rules.
