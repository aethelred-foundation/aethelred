# Aethelred Sovereign Public Proof Path Audit Pack

Run ID: `proof_1781531313894_ee7d56c0`

Seal ID: `seal_0c1e4fee119699938e9f648c`

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
2. Policy receipt `pol_5cb8a2386a89f52b64b9` authorized `finance.high_risk_transaction_review.seal`.
3. Jurisdiction report confirmed `AE-ADGM` for `AE-ADGM`.
4. External compute report `4600f386cb79ec0bf120e4f05400681f19ffed50bb60d139d1a6dd649df8a8f5` normalized `aethelred-docker-public-proof` as an upstream proof source.
5. Evidence bundle `0b312e9c-cebf-4cfa-96e9-5deccf3b5240` linked TEE-shaped evidence and zkML-shaped proof transcript.
6. Validator quorum `quorum_84c5591abf3161abee65` reached 4/3 accepts.
7. Liability route `route_2da89b57cf6d3a2f327b` bound sponsor, human controller, model-risk owner, operator, and auditor path.
8. Aethelred Seal `seal_0c1e4fee119699938e9f648c` bound the full decision evidence into one verifier-friendly record.
9. Anchor manifest `anchor_342df6b5847ebab2b53a3826` produced a local ledger anchor and chain-ready payload.
10. Pilot readiness gate returned `conditional-pass` with explicit production blockers.
11. Redaction manifest `c131679fd89e9734ab690f2cfb02263c95263fa51b21f0665b9a9305b53a460e` documented public export controls and data minimization.
12. Verifier onboarding pack `078c405adf86946a1935d82443c6bed445d06fc0f9687c608678b3c68bd7afb5` mapped verifier categories to production onboarding evidence.
13. Procurement readiness pack `c90263efcc789a250450b27b1d350fb45b2eb576a3e3b3c83a3d94b4f18278d6` converted proof artifacts into buyer due-diligence controls.
14. Sovereign differentiation scorecard `616769517566b91489b2845c642f2935467e99e1cabe695b4c4956b82527a166` documented the Aethelred layer above compute.
15. Auditor attestation `audit_a3baa461928c8c41cbc380be` signed the public proof artifact consistency boundary.

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
