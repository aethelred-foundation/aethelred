# Aethelred Public Proof Path Schema Catalog

This catalog describes the proof artifacts emitted by the Docker public proof
path. The schemas are intentionally explicit because the target reader is an
institutional buyer, regulator, auditor, validator candidate, or sovereign
infrastructure partner.

The public Docker path is not a production TEE or production zkML claim. It is a
pilot-grade packaging and verification path that demonstrates exactly what will
be replaced by real sovereign-cloud, TEE, zkML, HSM, auditor, and chain anchoring
controls.

## Artifact Map

| Artifact | Schema | Role |
|---|---|---|
| `proof-record.json` | `aethelred-public-proof-path-v0.2` | Full run record containing request, output, proof artifacts, seal, verifier report, and audit pack |
| `aethelred-seal.json` | `aethelred-seal-v0.2` | Portable AI decision seal binding core commitments |
| `policy-receipt.json` | `aethelred-policy-receipt-v0.2` | Signed policy decision and required-control checklist |
| `institutional-context.json` | `aethelred-institutional-context-v0.2` | Registry-backed tenant, policy, model, identity, deployment, and governance context |
| `jurisdiction-report.json` | `aethelred-jurisdiction-report-v0.2` | Jurisdiction, data residency, execution-region, and export-control evidence |
| `external-compute-report.json` | `aethelred-external-compute-report-v0.2` | Normalized upstream compute proof report for Docker, external confidential compute, sovereign cloud, or on-prem execution |
| `docker-attestation.json` | `aethelred-docker-attestation-v0.2` | Demo attestation transcript with container measurement and input/output commitments |
| `evidence-bundle.json` | `1.0.0` | Enterprise evidence bundle compatible with the existing evidence schema |
| `validator-quorum.json` | `aethelred-validator-quorum-v0.2` | Signed verifier votes across regulated verifier categories |
| `liability-route.json` | `aethelred-liability-route-v0.2` | Sponsor, human controller, model-risk owner, operator, auditor path, and escalation matrix |
| `key-custody-manifest.json` | `aethelred-key-custody-manifest-v0.2` | Demo signer posture plus production HSM/KMS requirements |
| `anchor-manifest.json` | `aethelred-anchor-manifest-v0.2` | Local ledger anchor and chain-ready payload for testnet or permissioned zone |
| `pilot-readiness-gate.json` | `aethelred-pilot-readiness-gate-v0.2` | Public proof, regulated pilot, and production readiness gates |
| `redaction-manifest.json` | `aethelred-redaction-manifest-v0.2` | Public export-control, field classification, and data minimization manifest |
| `verifier-onboarding-pack.json` | `aethelred-verifier-onboarding-pack-v0.2` | Verifier council onboarding requirements, roster template, and pilot legal-readiness checklist |
| `procurement-readiness-pack.json` | `aethelred-procurement-readiness-pack-v0.2` | Institutional buyer controls, required documents, and pilot commercial packaging |
| `sovereign-differentiation-scorecard.json` | `aethelred-sovereign-differentiation-scorecard-v0.2` | Signed Aethelred-vs-generic-verifiable-cloud scorecard for regulated buyers |
| `regulatory-evidence-index.json` | `aethelred-regulatory-evidence-index-v0.2` | Regulator-readable artifact index with SHA-256 commitments |
| `auditor-attestation.json` | `aethelred-auditor-attestation-v0.2` | Signed public-proof auditor attestation over artifact consistency |
| `public-verifier-manifest.json` | `aethelred-public-verifier-manifest-v0.2` | Public endpoints, claims, and claim boundaries |
| `verifier-report.json` | `aethelred-verifier-report-v0.2` | Machine verification result |
| `audit-pack.json` | `aethelred-audit-pack-v0.2` | Combined machine-readable audit pack |
| `audit-report.md` | Markdown | Human-readable audit report |

## Seal Commitments

The Aethelred Seal binds the high-value commitments that should remain portable
across public, permissioned, sovereign-cloud, and on-prem deployments:

| Commitment | Meaning |
|---|---|
| `model_hash` | Hash of the model identity, version, approval state, and risk rating |
| `input_hash` | Hash of the public-safe proof input |
| `output_hash` | Hash of the AI decision-support output |
| `policy_receipt_hash` | Hash of the signed policy receipt |
| `attestation_hash` | Hash of the Docker demo attestation transcript |
| `evidence_bundle_hash` | Hash of the enterprise evidence bundle |
| `institutional_context_hash` | Hash of the registry-backed institutional context |
| `jurisdiction_report_hash` | Hash of jurisdiction and data-residency evidence |
| `liability_route_hash` | Hash of the accountability route |
| `external_compute_report_hash` | Hash of normalized upstream compute proof acceptance evidence |
| `validator_quorum_hash` | Hash of verifier votes and quorum state |
| `assurance_plan_hash` | Hash of the assurance tier and production-blocker plan |

Post-seal artifacts such as `anchor-manifest.json`, `key-custody-manifest.json`,
`pilot-readiness-gate.json`, `sovereign-differentiation-scorecard.json`, and
`auditor-attestation.json` are verified by the machine verifier and evidence
index. They are post-seal because they describe how the sealed decision is
operated, anchored, promoted, differentiated, and audited.

## Verification Contract

The verifier must fail closed when any required artifact is tampered with. It
currently checks:

- input and output hash recomputation
- policy receipt hash and signature
- all required policy controls
- model, agent, and sponsor registry membership
- jurisdiction and residency controls
- liability route binding
- external compute report hash, signature, provider policy, and seal binding
- Docker attestation hash and signature
- evidence bundle hash
- validator quorum hash, threshold, vote hash, and vote signatures
- assurance tier minimum
- seal hash and signature
- key custody manifest hash and signature
- anchor manifest hash, signature, and seal binding
- pilot readiness gate hash, signature, and non-blocked state
- redaction manifest hash, signature, and raw-data export boundary
- verifier onboarding pack hash and signature
- procurement readiness pack hash, signature, and non-blocked buyer status
- regulatory evidence index hash, signature, and artifact hashes
- auditor attestation hash, signature, and artifact hashes
- append-only ledger chain verification

## Claim Boundary

This Docker path may claim:

- portable Aethelred Seal generation
- policy-native verification
- jurisdiction-aware evidence packaging
- regulated verifier quorum simulation
- liability-route packaging
- regulator/auditor evidence export
- local ledger anchoring and chain-ready payload generation
- external compute proof wrapping, including upstream confidential-compute proof transcripts

This Docker path must not claim:

- production hardware TEE execution
- production confidential-VM, Nitro, SGX, SEV-SNP, or sovereign-cloud integration without a real provider quote verifier
- production zkML proof generation
- production KMS/HSM key custody
- customer-funds suitability
- production regulated workload approval
- independent third-party audit completion

## Promotion To Production

To promote these schemas into pilot infrastructure:

1. Replace `docker-attestation.json` with a real Nitro, SGX, SEV-SNP, Intel TDX, or approved sovereign-cloud quote.
2. Replace synthetic `external-compute-report.json` inputs with provider-native quote verification for external confidential compute, sovereign cloud, or on-prem execution.
3. Replace the demo zkML transcript in `evidence-bundle.json` with production proof evidence or deterministic verifier evidence.
4. Replace ephemeral signers in `key-custody-manifest.json` with governed KMS/HSM signers.
5. Bind verifier identities in `validator-quorum.json` to legal entities and service terms.
6. Replace simulated `auditor-attestation.json` with an independent auditor signature.
7. Submit `anchor-manifest.json.chain_payload` to Aethelred testnet or a permissioned institutional zone.
