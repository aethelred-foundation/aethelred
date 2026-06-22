# Aethelred Sovereign Public Proof Path Audit Pack

Run ID: `proof_1781905140201_cb5e0b8f`

Seal ID: `seal_7bf07f8c87124d090ecd9ad5`

Use case: `finance.high_risk_transaction_review`

Tenant: `Aethelred Demo Bank`

Assurance target: Tier 4 - Tier 4 Sovereign Regulated AI Decision

## Verification Summary

| Result | Count |
|---|---:|
| Pass | 51 |
| Warning | 3 |
| Fail | 0 |

Overall status: **verified public proof path**

## Institutional Evidence Chain

1. Institutional context registered tenant, policy, model, agent, sponsor, and deployment mode.
2. Policy receipt `pol_cca1eb46927589234258` authorized `finance.high_risk_transaction_review.seal`.
3. Jurisdiction report confirmed `AE-ADGM` for `AE-ADGM`.
4. External compute report `342adadae4d00530a2de94517a4ab6c8f111c66c3e7c8218c6d60fd5083fa0ce` normalized `aethelred-docker-public-proof` as an upstream proof source.
5. Evidence bundle `bdaf4c0d-2f7f-49ba-9e5f-f0df4d810893` linked TEE-shaped evidence and zkML-shaped proof transcript.
6. Validator quorum `quorum_a159013530c1254cc698` reached 4/3 accepts.
7. Liability route `route_08b6da180d18ba0bd525` bound sponsor, human controller, model-risk owner, operator, and auditor path.
8. Aethelred Seal `seal_7bf07f8c87124d090ecd9ad5` bound the full decision evidence into one verifier-friendly record.
9. Anchor manifest `anchor_c0129d0c8d2fc67a797772b4` produced a local ledger anchor and chain-ready payload.
10. Pilot readiness gate returned `conditional-pass` with explicit production blockers.
11. Redaction manifest `a323067855002a977e7436ef1027601299aec2704e488d23abadbda80ae23203` documented public export controls and data minimization.
12. Verifier onboarding pack `628b78986ea6225cf23d6823aabe02160aceba21d4c17e7cbcabfb21f557cc77` mapped verifier categories to production onboarding evidence.
13. Procurement readiness pack `16a4febaaa57b8176b457d604e783ea6cba415629d3220631442ef3e61ac48f2` converted proof artifacts into buyer due-diligence controls.
14. Sovereign differentiation scorecard `b091ae5cf4533d72a3e854bdaffcef021d53406b2893e39b8707eea760448729` documented the Aethelred layer above compute.
15. Auditor attestation `audit_6c0d36cb9a2bdf35032e74b4` signed the public proof artifact consistency boundary.

## Production Promotion Blockers

| Blocker | Owner | Requirement |
|---|---|---|
| production-hardware-tee | compute-provider | Replace Docker demo attestation with Nitro, SGX, SEV-SNP, Intel TDX, or sovereign-cloud attestation. |
| production-zkml-proof | model-verification | Replace demo proof transcript with workflow-appropriate zkML or deterministic verifier evidence. |
| external-compute-quote-verifier | compute-adapter | Replace synthetic external proof transcripts with provider-native sovereign-cloud, confidential-VM, or on-prem quote verification. |
| governed-key-custody | protocol-governance | Move demo Ed25519 keys to governed KMS/HSM custody and publish key rotation policy. |
| external-audit-countersignature | assurance-council | Add independent security and regulatory auditor countersignature before regulated pilot claims. |

## Public Claim Boundary

- This Docker proof path is public-demo infrastructure. It does not claim hardware TEE execution.
- The attestation and zkML artifacts are structured demo transcripts, not production Nitro/SGX/SEV/TDX quotes or production proofs.
- Production use must replace the local demo signers with governed KMS/HSM custody and real verifier policy.
