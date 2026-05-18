# Sovereign Pilot Runbook

This runbook is for an Aethelred operator preparing a controlled demonstration
or pilot conversation with a regulated institution, sovereign cloud partner,
auditor, validator candidate, or government buyer.

## Operator Principle

Lead with the correct claim:

> Aethelred Seal can package a regulated AI decision with policy, identity,
> jurisdiction, verifier quorum, liability, audit export, and anchor-ready
> commitments. It can also wrap upstream compute proof from Docker, external
> confidential compute, sovereign cloud, or on-prem enclaves while keeping
> Aethelred as the policy and audit layer. This Docker path proves the public verification model. Production
> deployment requires real TEE or sovereign-cloud attestation, governed key
> custody, external auditor countersignature, and chain or permissioned-zone
> anchoring.

Do not overclaim TEE, zkML, HSM, production external-compute integration, production
uptime, customer-funds readiness, or independent audit completion from the
Docker path.

## Pre-Demo Checklist

1. Start from a clean local output directory or a dedicated validation directory.
2. Run the validation script.
3. Confirm the Docker service is healthy.
4. Generate one proof per relevant vertical.
5. Verify the latest seal and ledger.
6. Export the regulator pack.
7. Keep the production blockers visible rather than hiding them.

```bash
cd docs/demo/public-proof-path
npm run validate
docker compose up --build -d
curl -fsS http://127.0.0.1:8088/v1/health
```

## Scenario Runs

```bash
npm run run:finance
npm run run:healthcare
npm run run:carbon
```

Equivalent CLI form:

```bash
node src/cli.mjs run --scenario=finance
node src/cli.mjs run --scenario=healthcare
node src/cli.mjs run --scenario=carbon
node src/cli.mjs run --scenario=external-finance
```

Use `external-finance` when the buyer asks whether Aethelred is just a compute
runtime. The answer shown by the demo is: external compute proof can be an
upstream substrate, while Aethelred decides whether that proof is policy
compliant, jurisdiction-aware, auditable, liable, quorum-approved, and anchor ready.

## Public Verification

Use these endpoints during a demo:

| Endpoint | Use |
|---|---|
| `/` | Human proof console |
| `/v1/seals/latest/verify` | Machine verifier report |
| `/v1/external-compute/latest` | Upstream compute proof normalization and acceptance checks |
| `/v1/regulator-pack/latest` | Regulator/auditor export |
| `/v1/evidence-index/latest` | Artifact index and hash commitments |
| `/v1/redaction/latest` | Public export-control and data minimization evidence |
| `/v1/verifier-onboarding/latest` | Verifier council onboarding pack |
| `/v1/procurement/latest` | Institutional buyer readiness pack |
| `/v1/sovereign-differentiation/latest` | Signed 10x scorecard against generic verifiable compute |
| `/v1/anchor/latest` | Chain-ready anchor payload |
| `/v1/key-custody/latest` | Demo key posture and production custody requirements |
| `/v1/auditor/latest` | Simulated auditor attestation |
| `/v1/readiness/latest` | Public proof and pilot readiness gates |
| `/v1/ledger/verify` | Append-only ledger chain verification |

## Buyer Conversation Flow

1. Show the console and state the claim boundary.
2. Run a scenario that matches the buyer vertical.
3. Open the Aethelred Seal and explain the commitments.
4. Open the policy receipt and show required controls.
5. Open the external compute report and show why the upstream proof was accepted or rejected.
6. Open the jurisdiction report and show residency controls.
7. Open the validator quorum and show multi-category votes.
8. Open the liability route and show who is accountable.
9. Open the redaction manifest and show raw-data export controls.
10. Open the procurement pack and show buyer due-diligence controls.
11. Open the verifier onboarding pack and show how demo verifiers become legal pilot participants.
12. Open the 10x scorecard and show the Aethelred controls above generic compute proof.
13. Open the readiness gate and production blockers.
14. Open the regulator pack and evidence index.
15. Close with the production promotion plan.

## Production Promotion Gates

Before a regulated pilot, replace the Docker-only controls:

| Gate | Required owner | Exit evidence |
|---|---|---|
| Hardware attestation | Sovereign cloud or enclave operator | Nitro, SGX, SEV-SNP, TDX, or approved sovereign-cloud quote |
| External compute quote verification | Compute adapter owner | Provider-native confidential-compute, sovereign-cloud, or on-prem quote verification |
| zkML or deterministic verifier evidence | Model verification owner | Production proof or deterministic verifier transcript |
| HSM/KMS custody | Protocol governance and security owner | Key registry, rotation policy, and dual-control procedure |
| External auditor countersignature | Assurance council | Signed audit letter or auditor attestation |
| Legal verifier identities | Validator council | Legal entity mapping, terms, and obligations |
| Chain or permissioned-zone anchor | Protocol/operator team | Accepted anchor transaction or private-zone commit |

## Failure Handling

If `/v1/seals/latest/verify` returns `valid: false`:

1. Stop the demo flow and open `verifier-report.json`.
2. Identify the first failed check.
3. Do not generate a replacement proof until the failing artifact is understood.
4. Export the broken `proof-record.json` for internal debugging.
5. Rerun with a clean output directory only after root cause is known.

If the ledger verification fails:

1. Treat the local proof directory as compromised.
2. Preserve the directory for incident review.
3. Restart with a clean output directory.
4. Do not present ledger continuity claims from the compromised directory.

## Demo Reset

The Docker output directory is ignored by git. To reset:

```bash
cd docs/demo/public-proof-path
docker compose down
rm -rf out
docker compose up --build -d
```

Do not reset output directories during a buyer review unless the purpose is
explicitly to demonstrate a clean-room proof generation.
