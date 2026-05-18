# External Compute Interop Strategy

This proof path treats external confidential compute, sovereign cloud, and on-prem enclaves as
possible upstream compute substrates. Aethelred does not need to pretend those
systems do not exist. The sharper position is:

> External compute can prove that execution happened. Aethelred proves that the
> resulting AI decision was authorized, policy-compliant, jurisdiction-aware,
> liable, quorum-approved, auditable, and anchor-ready.

## Current Public Demo

The `external-finance` scenario generates a synthetic external confidential-compute
transcript and then runs it through Aethelred's adapter policy.

The adapter accepts the proof only when all required checks pass:

| Check | Meaning |
|---|---|
| `provider-registered` | The upstream compute provider is in Aethelred's substrate registry |
| `attestation-type-supported` | The provider adapter accepts the attestation type |
| `model-hash-bound` | The external proof commits to the model identity and version |
| `input-hash-bound` | The external proof commits to the public-safe input hash |
| `output-hash-bound` | The external proof commits to the output hash |
| `proof-hash-present` | The provider proof has a stable commitment |
| `execution-region-allowed` | The execution region is allowed for the policy jurisdiction |
| `no-public-data-export` | The provider did not export raw regulated data into public artifacts |

If any required check fails, the verifier fails closed.

## Why This Is Strategic

This reframes third-party compute from a one-to-one threat into a substrate benchmark:

| Layer | External compute | Aethelred sovereign layer |
|---|---|---|
| Execution | Confidential VM or verifiable compute workload | Accepts or rejects upstream proof under regulated policy |
| Developer proof | Workload and attestation commitment | Decision seal with policy, identity, jurisdiction, liability, quorum, audit, and anchor evidence |
| Buyer | Developers and agent builders | Banks, health systems, sovereign cloud programs, auditors, regulators, and government buyers |
| Risk owner | Application/operator centric | Sponsor, human controller, model-risk owner, protocol operator, verifier quorum, auditor path |
| Output | Compute proof | Regulator-ready decision evidence pack |

## Production Adapter Requirements

Before Aethelred can make production claims about an external compute provider,
each adapter needs:

1. Provider-native quote parser and verifier.
2. Freshness, nonce, measurement, and workload identity checks.
3. Policy-bound measurement allowlist.
4. Region and jurisdiction policy mapping.
5. Raw-data export controls and audit retention rules.
6. Provider incident, support, and SLA terms.
7. Legal claim boundary approved by Aethelred governance and counsel.

## Demo Commands

```bash
cd docs/demo/public-proof-path
npm run run:external
node src/cli.mjs external-report
node src/cli.mjs sovereign-scorecard
node src/cli.mjs verify
```

HTTP endpoints:

```text
GET /v1/external-compute/latest
GET /v1/sovereign-differentiation/latest
GET /v1/seals/latest/verify
GET /v1/regulator-pack/latest
```
