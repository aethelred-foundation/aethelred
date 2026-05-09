# Aethelred Infinity Sandbox — Core Changelog

All notable changes to `aethelred-sandbox-core` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Each release lists the new tier-1 enterprise modules added, the cumulative
unit-test count, and the public surface that was wired through
`aethelred_sandbox_core::prelude::*`.

---

## [0.2.33] - 2026-05-09

Federated AI / multi-party governance cluster: per-participant federated
enrolment, secure-aggregation run logs, data clean-room sessions, and
chains of cross-party TEE attestations. Closes the **federated-AI
governance surface** that aligns with Aethelred's positioning — pairs
naturally with `federated_verify`, `tee_verify`, and
`differential_privacy`.

### Added

- `federated_participant_register` — per-participant federated learning
  enrolment with `Invited -> Enrolled -> Active -> (Suspended <-> Active)
  -> Withdrawn | Terminated` lifecycle. Consent scope (SingleRound /
  CohortStudy / Continuous / BenchOnly), contribution mode
  (LocalTraining / SecureAggregation / DpLocal / DpCentral /
  TeeSharedData), per-round contribution log with sample/weight
  aggregates.
- `secure_aggregation_log` — per-round secure-aggregation operational
  log with `Pending -> Receiving -> Aggregating -> Completed | Aborted`
  lifecycle. Seven aggregation protocols (FedAvg / SecureAgg /
  Homomorphic / ThresholdSecretSharing / Tee / DpAggregation / Custom),
  per-participant update integrity flags, post-hoc disqualification,
  k-anonymity minimum-participants gate at completion, and five abort
  reasons.
- `clean_room_session` — data clean-room session register with
  `Provisioned -> DataLoaded -> InUse -> Sealed -> Destroyed` lifecycle.
  Five query policies, per-session DP epsilon budget enforcement at
  query submission, query-level status (Pending / Running / Completed /
  Failed / PolicyBlocked) with budget-charging only on Completed,
  budget_exhausted() filter.
- `federated_attestation_chain` — chains of cross-party TEE attestations
  with `Building -> Sealed -> (Verified | Repudiated)` lifecycle.
  LinkRelation (Root / Parent / Sibling / Witness) with parent-link
  validation, per-link verdict (Pending / Verified / Failed / Skipped),
  quorum threshold + any-failed gate at finalisation, links to
  aggregation rounds and clean-room sessions.

### Tests

- 97 new unit tests (federated_participant_register 20,
  secure_aggregation_log 23, clean_room_session 26,
  federated_attestation_chain 28).
- Cumulative sandbox-core lib: **3,959 tests / 0 failures / ~1.2s**.

### Prelude

- `FederatedParticipantRegister`, `FederatedParticipant`,
  `ParticipantStage`, `ConsentScope`, `ContributionMode`,
  `RoundContribution`, `FederatedParticipantEvent`
- `SecureAggregationLog`, `AggregationRound`, `AggregationRoundStage`,
  `AggregationProtocol`, `ParticipantUpdate`, `AbortReason`,
  `AggregationRoundEvent`
- `CleanRoomSessionRegister`, `CleanRoomSession`, `CleanRoomSessionStage`,
  `QueryPolicy`, `QueryRecord`, `QueryStatus`, `CleanRoomSessionEvent`
- `FederatedAttestationChainRegistry`, `AttestationChain`, `ChainStage`,
  `AttestationLink`, `LinkRelation`, `LinkVerdict`,
  `AttestationChainEvent`

---

## [0.2.32] - 2026-05-09

Customer-facing operations cluster: support ticket register, customer
feedback (NPS / CSAT / CES) register, customer-visible knowledge base,
and subscription renewal pipeline. Closes the **customer-success layer**
that internal operations modules don't cover.

### Added

- `support_ticket_register` — external customer tickets with
  `Open -> Assigned -> InProgress -> AwaitingCustomer -> (Resolved ->
  Closed) | Cancelled` lifecycle (re-open allowed). Eight channels,
  four priorities (P0-P3), threaded replies, CSAT capture, SLA
  deadlines with `response_overdue` / `resolution_overdue` queries.
- `feedback_register` — NPS (0-10), CSAT (1-5), CES (1-7), qualitative,
  feature requests, bug reports, churn-risk signals. Numeric /
  qualitative constructors validate score ranges; NPS auto-classifies
  Promoter / Passive / Detractor. `nps_basis_points()`, `mean_csat()`,
  `mean_ces()` aggregates with tenant / period filters.
- `knowledge_base_register` — customer-facing KB with eight categories,
  `Drafted -> InReview -> Published -> (Updated -> Published) |
  Archived` lifecycle, monotonic version history with content SHA-256,
  view/vote counters, `low_helpfulness()` rewrite-candidates query.
- `renewal_register` — subscription renewal pipeline with `Upcoming ->
  InNegotiation -> (Renewed | Churned | Expired)` lifecycle. ARR in
  micro-units; auto-derived SizeDelta (Upsell / Flat / Downgrade);
  health signals (Green / Yellow / Red), at_risk() filter,
  total_retained_arr_micro / total_lost_arr_micro aggregates, and
  nrr_basis_points() board-level Net Revenue Retention.

### Tests

- 102 new unit tests (support_ticket_register 27, feedback_register 26,
  knowledge_base_register 23, renewal_register 26).
- Cumulative sandbox-core lib: **3,862 tests / 0 failures / ~1.2s**.

### Prelude

- `SupportTicketRegister`, `SupportTicket`, `TicketStage`,
  `TicketChannel`, `TicketPriority`, `TicketCategory`, `TicketReply`,
  `TicketEvent`, `CsatRating`
- `FeedbackRegister`, `FeedbackResponse`, `FeedbackKind`,
  `FeedbackChannel`, `NpsSegment`
- `KnowledgeBaseRegister`, `KnowledgeBaseArticle`, `ArticleCategory`,
  `ArticleStage`, `KbArticleVersion`, `KbArticleEvent`
- `RenewalRegister`, `RenewalOpportunity`, `RenewalStage`, `SizeDelta`,
  `HealthSignal`, `RenewalEvent`

---

## [0.2.31] - 2026-05-09

Infrastructure governance cluster: Terraform/IaC plan-and-apply
register, Kubernetes manifest register, infrastructure drift detection,
and capacity planning. Closes the **infrastructure substrate** layer
beneath the existing service-level surface (`service_catalog`,
`deployment_pipeline`).

### Added

- `terraform_plan_register` — IaC plan-and-apply register with
  `Planned → Reviewed → Approved → Applying → (Applied | Failed |
  Discarded | RolledBack)` lifecycle. Reviewer and approver must differ
  from proposer (separation of duty enforced at issue site). Policy
  gates (Sentinel / OPA) with `Pending | Pass | SoftFail | HardFail |
  Override` verdicts block approval when any gate is Pending or
  HardFail. Resource changes broken out into add/update/replace/destroy
  counts; `is_destructive()` and `destructive()` queries surface
  high-risk plans. Maps to SOC 2 CC8.1, NIST 800-53 CM-3.
- `kubernetes_manifest_register` — declared cluster-state inventory
  with seventeen resource kinds (Deployment, StatefulSet, DaemonSet,
  Job, CronJob, Service, Ingress, ConfigMap, Secret, Role, RoleBinding,
  ClusterRole, ClusterRoleBinding, NetworkPolicy, PodSecurityPolicy,
  Namespace, Other), `Drafted → Applied → Active → (Replaced | Deleted)`
  lifecycle, container image references with digest pinning,
  `unpinned_workloads()` query that flags active workloads with
  un-pinned images (CIS K8s benchmark violation), and RBAC binding
  inventory. Maps to CIS Kubernetes Benchmark, SOC 2 CC8.1, PCI 6.x.
- `infrastructure_drift` — drift detection register comparing declared
  vs actual state with `Detected → Triaged → RemediationPlanned →
  (Remediated | Accepted) | FalsePositive` lifecycle, field-level
  deltas, severity (Info / Low / Medium / High / Critical), and
  `actionable()` / `aged(now, days)` queries. Sources include
  Terraform, Kubernetes, Pulumi, CloudFormation, Helm, Ansible. Maps to
  SOC 2 CC8.1, NIST 800-53 CM-8, CIS 4.1-4.3.
- `capacity_planning` — utilisation sampling (capacity-bounded, FIFO-
  evicted) plus operator recommendations with `Open → InReview →
  Accepted → Implemented | Rejected | Stale` lifecycle. Six
  recommendation kinds (ScaleUp / ScaleDown / ScaleOut / ScaleIn /
  RightSize / Migrate); `under_utilised(metric, threshold)` and
  `over_utilised()` resource filters; `estimated_total_saving_micro()`
  aggregates open cost-saving recommendations. Maps to FinOps
  "Optimize", SOC 2 A1.1, NIST 800-53 SC-5.

### Tests

- 104 new unit tests (terraform_plan_register 30,
  kubernetes_manifest_register 24, infrastructure_drift 22,
  capacity_planning 28).
- Cumulative sandbox-core lib: **3,760 tests / 0 failures / ~1.2s**.

### Prelude

- `TerraformPlanRegister`, `TerraformPlan`, `TerraformPlanStage`,
  `TerraformPolicyGate` (renamed to avoid collision with
  `policy::PolicyGate`), `PolicyVerdict`, `ResourceChange`,
  `ResourceChangeKind`, `TerraformPlanEvent`
- `KubernetesManifestRegister`, `KubernetesManifest`, `ManifestKind`,
  `K8sManifestStage`, `ContainerImage`, `RbacBinding`,
  `K8sManifestEvent`
- `InfrastructureDriftRegister`, `DriftRecord`, `DriftStage`,
  `InfraDriftSeverity` and `InfraDriftEvent` (renamed to avoid
  collisions with `drift::DriftSeverity` / `drift::DriftEvent`),
  `DriftSource`, `FieldDelta`
- `CapacityPlanningRegistry`, `ResourceCapacity`, `UtilizationSample`,
  `CapacityMetricKind`, `CapacityRecommendation`, `RecommendationKind`,
  `CapacityRecommendationStage`

---

## [0.2.30] - 2026-05-08

Workforce safety / people-controls cluster: pre-employment background
checks, NDA / confidentiality agreement tracking, mandatory security
training, and physical (badge) access registry. Closes the **people-side
audit-evidence loop** alongside the v0.2.27 IAM cluster — auditors now
see the full pre-employment, contractual, training, and physical-access
trail for every workforce member.

### Added

- `background_check_register` — pre-employment screening with
  `Initiated → Consent → InProgress → (Cleared | Adverse | Inconclusive
  | Withdrawn)` lifecycle. Per-line check types (Criminal / Employment /
  Education / Credit / Identity / DrugScreen / Sanctions / Licensure /
  References / RightToWork) with auto-derived terminal stage from line
  results. `latest_cleared_for_subject(id)` is the auditor's "is this
  person cleared?" query. Maps to SOC 2 CC1.4, ISO 27001 A.7.1.1,
  NIST 800-53 PS-3, FCRA / GDPR consent.
- `confidentiality_agreement` — NDA register with four kinds (OneWay /
  Mutual / MultiParty / EmbeddedInOther), `Drafted → Sent → Signed →
  InEffect → (Expired | Terminated)` lifecycle, signature collection
  with required-party enforcement (`signatures_complete()`), term-based
  default expiry, and overdue-review query. Maps to ISO 27001 A.13.2.4,
  SOC 2 CC2.2.
- `security_training_register` — mandatory training compliance with
  course definitions (recurrence cadence + passing threshold) and per-
  subject enrollments through `Assigned → InProgress → (Completed |
  Failed | Exempt | Withdrawn)` lifecycle. `due_for_renewal(course,
  now)` flags subjects whose latest satisfying completion is older than
  the cadence; `overdue(now)` flags missed deadlines. Maps to ISO 27001
  A.7.2.2, SOC 2 CC1.4, NIST 800-53 AT-2, HIPAA §164.530(b), PCI-DSS
  12.6.
- `physical_access_register` — facility / badge registry with four-tier
  facility classification (Public / Internal / Restricted / Critical),
  six credential kinds (Badge / Pin / Biometric / Mobile / HardwareKey
  / Escorted), and per-grant lifecycle `Requested → Approved → Active →
  (Suspended | Expired | Revoked)` with Denied branch. Restricted /
  Critical tiers enforce **separation of duty** at approve() — approver
  must differ from sponsor. Maps to ISO 27001 A.11.1.1-3, SOC 2 CC6.4,
  NIST 800-53 PE-2/3, HIPAA §164.310.

### Tests

- 108 new unit tests (background_check_register 30,
  confidentiality_agreement 24, security_training_register 29,
  physical_access_register 25).
- Cumulative sandbox-core lib: **3,656 tests / 0 failures / ~1.2s**.

### Prelude

- `BackgroundCheckRegister`, `BackgroundCheckRecord`, `ScreeningStage`,
  `CheckType`, `CheckResult`, `CheckLine`
- `ConfidentialityAgreementRegistry`, `ConfidentialityAgreement`,
  `NdaKind`, `NdaStage`, `NdaPartyEntry`, `NdaPartyRole`,
  `NdaSignatureRecord`
- `SecurityTrainingRegister`, `Course`, `CourseKind`, `Enrollment`,
  `EnrollmentStage`
- `PhysicalAccessRegister`, `Facility`, `FacilityTier`,
  `PhysicalAccessGrant`, `PhysicalGrantStage`, `CredentialKind`,
  `PhysicalAccessEvent`

---

## [0.2.29] - 2026-05-08

Vendor & third-party governance cluster: GDPR Art 28 subprocessor list,
vendor due-diligence questionnaire scoring, Data Processing Agreement
inventory, and structured vendor offboarding. Closes the third-party
governance evidence loop alongside existing `third_party_risk` and
`supply_chain_sbom` modules.

### Added

- `subprocessor_register` — public-facing GDPR Art 28 subprocessor list
  with `Proposed → NotificationSent → Approved | Objected | Withdrawn →
  Active → Retired` lifecycle, customer-objection tracking with
  auto-stage transition, notice-window enforcement
  (`in_notice_window(now)` / `notice_window_expired(now)`), and
  special-category-data flagging.
- `vendor_assessment` — DDQ register with eight question domains
  (Security / Privacy / Compliance / Financial / Operational /
  BusinessContinuity / AiMl / Other), weighted scoring (1-10 weight,
  0-5 score, returned in basis points 0-500), per-domain rollup, and
  `Drafted → Sent → InReview → Completed | Cancelled` lifecycle with
  Verdict (`Approved | ApprovedWithConditions | Rejected | Pending`).
  Maps to SOC 2 CC9.2, ISO 27001 A.15.1.1, NIST 800-53 SR-3.
- `data_processing_agreement` — DPA / BAA / SCC contract inventory
  with `Drafted → InReview → Signed → InEffect → (Renewed | Expired |
  Terminated)` lifecycle, signature records, periodic-review tracking
  with cadence enforcement, document URI + SHA-256, and
  `link_renewal(older, newer)` chaining successors. Maps to GDPR Art 28,
  HIPAA BAA, CCPA service-provider contracts.
- `vendor_offboarding` — structured offboarding workflow with
  per-event tasks (RevokeAccess / ReclaimCredentials / ReturnData /
  ConfirmDataDestruction / ConfirmSubprocessorDestruction /
  SettleFinalInvoice / TerminateContract / UpdateRegisters /
  KnowledgeTransfer / NotifyCustomers), task-level status, trigger
  taxonomy (ContractEnd / Replacement / SecurityIncident / etc.), and
  Completion Certificate issuance on close. Maps to GDPR Art 28(3)(g),
  HIPAA §164.504(e)(2)(ii)(I), SOC 2 CC9.2, ISO 27001 A.15.2.1.

### Tests

- 93 new unit tests (subprocessor_register 21, vendor_assessment 23,
  data_processing_agreement 22, vendor_offboarding 27).
- Cumulative sandbox-core lib: **3,548 tests / 0 failures / ~1.2s**.

### Prelude

- `SubprocessorRegister`, `SubprocessorEntry`, `SubprocessorStage`,
  `SubprocessorEvent`, `ProcessingPurpose`, `SubprocessorDataCategory`,
  `CustomerObjection`
- `VendorAssessmentRegistry`, `VendorAssessment`,
  `VendorAssessmentStage`, `VendorAssessmentQuestion`, `QuestionDomain`,
  `VendorAssessmentVerdict`
- `DataProcessingAgreementRegistry`, `DataProcessingAgreement`,
  `AgreementKind`, `AgreementStage`, `DpaSignatureRecord`,
  `DpaReviewRecord`
- `VendorOffboardingRegistry`, `VendorOffboardingEvent`,
  `VendorOffboardingStage`, `OffboardingTask`,
  `VendorOffboardingTaskKind`, `VendorOffboardingTaskStatus`,
  `OffboardingTrigger`, `VendorOffboardingCertificate`

---

## [0.2.28] - 2026-05-08

FinOps & cost-control cluster: per-entity cost allocation, budget
tracking with variance, internal chargeback reports, and effective-dated
rate cards. Closes the FinOps Foundation framework loop —
`billing_meter` measures usage, this cluster decides who pays.

### Added

- `cost_attribution` — per-entity cost allocation in micro-units (1 USD
  = 1_000_000) with four allocation methods: `DirectAttribution`,
  `EvenSplit`, `UsageProrate` (weighted), `Custom` (caller-supplied per-
  owner amounts validated against total). Sum of per-owner amounts
  always equals input total — last entry absorbs remainder. Maps to
  FinOps Foundation "Allocation" capability.
- `budget_register` — per-period budgets with cumulative spend, three-
  level watermarks (warning / critical / exceeded as percentages), and
  deterministic state recomputation
  (`OnTrack | Warning | Critical | Exceeded`) on every spend / credit /
  amount change. `alerting()` and `exceeded()` queries power FinOps
  dashboards.
- `chargeback_report` — invoice-style internal reports with
  `Draft → Issued → Disputed | Settled` lifecycle, line items,
  post-issue adjustments, and `recipient_total_micro()` aggregation.
  Maps to FinOps Foundation "Showback / Chargeback" capability.
- `rate_card_versioning` — effective-dated rate cards with
  `Draft → Active → Superseded | Discarded` lifecycle, half-open window
  semantics ([effective_at, effective_until)), overlap detection at
  activation (drafts can be created with overlapping windows so
  successors stage cleanly before `supersede(older, newer)` closes the
  predecessor), and `current_at(card, tenant, now)` resolution.

### Tests

- 101 new unit tests (cost_attribution 24, budget_register 26,
  chargeback_report 23, rate_card_versioning 28).
- Cumulative sandbox-core lib: **3,455 tests / 0 failures / ~1.2s**.

### Prelude

- `CostAttributionRegistry`, `CostEntry`, `Allocation`,
  `AllocationMethod`
- `BudgetRegister`, `Budget`, `BudgetState`, `Watermarks`, `SpendEvent`
- `ChargebackRegister`, `ChargebackReport`, `ChargebackLineItem`,
  `ChargebackAdjustment`, `ChargebackStage`
- `RateCardRegistry`, `RateCardVersion`, `RateLine`,
  `RateCardVersionStatus`

---

## [0.2.27] - 2026-05-08

Identity & access governance cluster: periodic access certification,
segregation-of-duties detection, privileged-access management (PAM),
and joiner/mover/leaver identity lifecycle. Closes the people-side of
SOC 2 CC6.x and ISO 27001 A.9.2.x.

### Added

- `access_certification` — quarterly access-review campaigns with
  `Pending → InProgress → Completed | Cancelled` lifecycle, per-entitlement
  `Reaffirmed | RevokeRequested | ModifyRequested | Pending` verdict,
  and completion gate that rejects unresolved entitlements. Maps to
  SOC 2 CC6.3, ISO 27001 A.9.2.5, PCI-DSS 7.x.
- `segregation_of_duties` — declared SoD rule registry with
  `evaluate(tenant, principal, holdings)` returning fired rules,
  conflict kinds (Financial / Operational / Privacy / Compliance /
  Security), and violation lifecycle
  (Open → AcceptedWithCompensation | Remediated | FalsePositive). Maps
  to SOX §404, SOC 2 CC6.1, NIST 800-53 AC-5, PCI 6.4.
- `privileged_access_register` — PAM grant register with
  `Requested → Approved → Active → Expired | Revoked` lifecycle
  (Denied branch from Requested), approver-must-differ-from-principal
  enforcement, justification + linked ticket fields, and
  `overdue_revocation(now)` / `expiring_within(now, hours)` queries.
  Maps to SOC 2 CC6.1, NIST 800-53 AC-6, PCI-DSS 7.2, ISO 27001 A.9.2.3.
- `identity_lifecycle` — joiner/mover/leaver/termination/LOA event
  registry with `Requested → InProgress → Completed | Cancelled`
  lifecycle, per-event provisioning tasks
  (CreateAccount / DisableAccount / AssignRole / IssueCredential / ...)
  with task-level status (Pending / InProgress / Completed / Failed /
  Skipped), `closed_with_failures()` audit query, and
  `overdue(now)` for past-effective-date open events. Maps to SOC 2
  CC6.2, ISO 27001 A.9.2.1-2, NIST 800-53 AC-2.

### Tests

- 96 new unit tests (access_certification 23, segregation_of_duties 26,
  privileged_access_register 20, identity_lifecycle 27).
- Cumulative sandbox-core lib: **3,354 tests / 0 failures / ~1.2s**.

### Prelude

- `AccessCertificationRegistry`, `CertificationCampaign`,
  `AccessCampaignStage`, `Entitlement`, `EntitlementKind`,
  `AccessReviewVerdict`
- `SegregationOfDutiesRegistry`, `SodRule`, `SodViolation`,
  `ConflictKind`, `EvaluationHit`, `SodViolationStatus`
- `PrivilegedAccessRegister`, `PrivilegedGrant`, `PrivilegeKind`,
  `GrantStage`, `PrivilegedGrantEvent`
- `IdentityLifecycleRegistry`, `IdentityEvent`, `IdentityEventKind`,
  `IdentityEventStage`, `ProvisioningTask`, `IdentityTaskKind`,
  `IdentityTaskStatus`

---

## [0.2.26] - 2026-05-08

Enterprise risk & audit prep cluster: top-level enterprise risk
register, control test history, external audit finding tracker, and
regulatory correspondence log. Closes the audit-prep loop — the four
registers compliance teams pull out before a SOC 2 / ISO 27001 / regulator
examination.

### Added

- `enterprise_risk_register` — top-level board-level risk register with
  `Identified → Analyzed → Treating → Monitored → Closed` lifecycle
  (with `Monitored → Treating` re-treatment loop), inherent + residual
  ratings (likelihood × impact), treatment strategy
  (Accept / Mitigate / Transfer / Avoid), control bindings, board
  acceptance flag, annual review tracking, and `top_by_residual()` /
  `requiring_board_attention()` queries. Maps to ISO 31000, COSO ERM,
  NIST 800-37, SOC 2 CC3.2.
- `control_test_register` — operational evidence-of-operation for
  compliance controls: per-test outcome (Passed / Failed / Exception /
  NotApplicable), method (Inspection / Observation / Reperformance /
  Inquiry / Automated), remediation tracking with status
  (NotStarted → InProgress → Implemented → Verified), and
  `period_summary(period)` aggregate statistics. Maps to SOC 2 Type II,
  ISO 27001 9.2, PCI-DSS 12.x, NIST 800-53 CA-7.
- `audit_finding_tracker` — external audit finding registry with
  `Open → AcceptedByMgmt → Remediating → Remediated → Verified` lifecycle
  (plus `Disputed`, `Withdrawn`, `Closed` branches and
  `Remediated → Remediating` re-test loop), severity (Critical / High /
  Moderate / Low / Informational), source (Soc2 / Iso27001 / PciQsa /
  Hipaa / Sox / Internal / Regulator / CustomerAudit / PenTest), linked
  controls and risks, and `material_open()` / `overdue(now)` queries.
- `regulatory_correspondence` — bidirectional log of regulator
  communications: direction (Inbound / Outbound), kind
  (InformationRequest / ExaminationNotice / SelfDisclosure / Inquiry /
  Response / Filing / ExaminationFindings / EnforcementAction /
  NoActionLetter / General), `Logged → Acknowledged → ResponseDrafted →
  ResponseSubmitted → Closed` lifecycle (with re-draft loop after
  rejection), document storage URI + SHA-256, response deadline
  tracking, and `chronological()` / `for_finding()` / `overdue()`
  queries. Maps to SEC 17a-4, FFIEC, FCA Principle 11, SOX §906.

### Tests

- 84 new unit tests (enterprise_risk_register 25, control_test_register
  20, audit_finding_tracker 20, regulatory_correspondence 19).
- Cumulative sandbox-core lib: **3,258 tests / 0 failures / ~1.2s**.

### Prelude

- `EnterpriseRiskRegister`, `EnterpriseRisk`, `RiskCategory`,
  `RiskRating`, `RiskStage`, `TreatmentStrategy`,
  `EnterpriseControlReference`, `EnterpriseRiskEvent`
- `ControlTestRegister`, `ControlTest`, `TestMethod`, `TestOutcome`,
  `ControlRemediationStatus`, `ControlTestPeriodSummary`
- `AuditFindingTracker`, `AuditFinding`, `AuditFindingStage`,
  `AuditFindingSeverity`, `AuditSource`, `AuditFindingEvent`
- `RegulatoryCorrespondence`, `CorrespondenceItem`, `CorrespondenceKind`,
  `CorrespondenceDirection`, `CorrespondenceStatus`,
  `CorrespondenceEvent`

---

## [0.2.25] - 2026-05-08

Incident-response operational maturity cluster: real-time war-room state,
escalation matrices, forensic captures with chain-of-custody, and
public status pages. Closes the operational loop on **active** incident
coordination — existing modules tracked the records of past incidents;
this cluster covers what's happening right now.

### Added

- `incident_war_room` — real-time war-room state with
  `Activated → InProgress → Mitigated → Resolved` lifecycle (with
  re-flare from Mitigated → InProgress), role assignments
  (Commander / CommsLead / TechLead / Scribe / Sme / ExecSponsor /
  CustomerLiaison), evolving hypothesis, customer-facing summary,
  timeline, and in-flight action items. `missing_commander()` flags
  active war rooms without a commander assigned. Maps to NIST 800-53
  IR-4, ITIL incident management, ISO 27035.
- `escalation_matrix` — per-(severity, service) escalation policies
  with `next_step(now, last_ack_at)` returning the tier that should
  fire based on elapsed time without ack. Tenant-wide defaults via
  `service_id == ""`. Tier ordering enforced (Primary → Secondary →
  Manager → Director → Executive). Maps to ITIL escalation, NIST
  800-53 IR-6, SOC2 CC7.4.
- `forensic_capture` — chain-of-custody preserved evidence registry:
  SHA-256 integrity hash, custody event log (Captured / Verified /
  VerificationFailed / Transferred / Released / Sealed / Destroyed),
  metadata-only storage with out-of-band byte URI, `verify()` against
  externally-recomputed hash with automatic custody-break detection,
  `broken_custody()` and `sealed()` queries. Maps to NIST 800-86,
  ISO 27037, SANS chain-of-custody.
- `status_page` — public-facing status board: per-component operational
  status with worst-severity rollup, public incident lifecycle
  (`Investigating → Identified → Monitoring → Resolved →
  PostmortemPublished` with re-flare allowed from Monitoring back to
  Investigating), impacted-component tagging, postmortem URLs, and
  `summary(generated_at, recent_count)` rendering for HTML/JSON pages.
  Maps to Statuspage / Atlassian Statuspage / instatus pattern.

### Tests

- 93 new unit tests (incident_war_room 28, escalation_matrix 20,
  forensic_capture 21, status_page 24).
- Cumulative sandbox-core lib: **3,174 tests / 0 failures / ~1.2s**.

### Prelude

- `IncidentWarRoomRegistry`, `WarRoom`, `WarRoomStage`,
  `WarRoomActionItem`, `WarRoomRole`, `WarRoomRoleAssignment`,
  `WarRoomTimelineEntry`
- `EscalationMatrix`, `EscalationPolicy`, `EscalationStep`,
  `EscalationTier`, `EscalationSeverity`, `NextStep`
- `ForensicCaptureRegistry`, `ForensicCapture`, `CustodyAction`,
  `CustodyEvent`, `ForensicEvidenceKind`
- `StatusPage`, `StatusComponent`, `OperationalStatus`,
  `StatusIncidentStage`, `StatusIncidentUpdate`, `PublicIncident`,
  `PageSummary`

---

## [0.2.24] - 2026-05-08

Operational AI safety cluster: structured model evaluation harness,
automated-decision appeals (GDPR Art 22), per-agent action guardrails,
and sampled inference audit. Closes the operational governance loop on
agent runtime safety, decision recourse, and continuous monitoring.

### Added

- `model_evaluation_harness` — release-gate eval suites with
  `Pending → Running → (Passed | Failed | Aborted)` lifecycle, per-benchmark
  threshold + direction (higher / lower is better), automatic pass/fail
  derivation from measurements, and `latest_passed_for_model()` query.
  Maps to NIST AI RMF GOVERN-1.4, EU AI Act Art 15, ISO/IEC 23053.
- `automated_decision_appeal` — GDPR Art 22 appeal register with
  `Filed → Verified → EvidenceCollection → UnderReview → (Upheld |
  PartiallyOverturned | Overturned | Withdrawn)` lifecycle, evidence
  inventory, reviewer assignment, mandatory reasoned outcome on overturn,
  and `overturned() / high_impact() / overdue(now)` queries.
- `agent_guardrail` — per-agent runtime action policy: tool allowlist,
  approval-required tools, prohibited content categories, output-token
  cap, tool-calls-per-turn cap, and `evaluate(action)` returning
  `Allow | RequireApproval(reason) | Deny(reason)`. Fail-closed default
  for unregistered agents. Maps to NIST AI RMF MANAGE-2.4, EU AI Act
  Art 14, OWASP / MITRE ATLAS agent action policy.
- `inference_audit` — capacity-bounded sampling log of production
  inferences with sampling policy (Periodic / LowConfidence /
  FlaggedOnly / All), reviewer verdicts (Correct / Borderline /
  Incorrect / Unsafe / Inconclusive), `regressions()` + `unreviewed()`
  queries, and FIFO eviction at capacity. Maps to NIST AI RMF MEASURE-2.7
  and EU AI Act Art 12.

### Tests

- 87 new unit tests (model_evaluation_harness 25, automated_decision_appeal
  21, agent_guardrail 25, inference_audit 16).
- Cumulative sandbox-core lib: **3,081 tests / 0 failures / ~1.2s**.

### Prelude

- `EvaluationHarness`, `EvaluationRun`, `EvaluationRunStage`, `Benchmark`,
  `BenchmarkKind`, `BenchmarkStatus`
- `AppealRegister`, `Appeal`, `AppealEvent`, `AppealStage`,
  `AppealDecisionImpact`, `AppealEvidenceItem`, `AppealOriginalDecision`
- `AgentGuardrail`, `AgentGuardrailRegistry`, `GuardrailDecision`,
  `ProposedAction`
- `InferenceAuditLog`, `CapturedInference`, `InferenceReviewVerdict`,
  `SamplingPolicy`

---

## [0.2.23] - 2026-05-08

Privacy & data-governance cluster: DPIA register (GDPR Art 35),
privacy-rights request handling (GDPR Art 15-22 / CCPA), encryption-at-rest
inventory, and data retention class registry. Closes the GDPR / CCPA /
HIPAA / SOX evidence loop on the controller-side governance surface.

### Added

- `dpia_register` — Data Protection Impact Assessment register with
  `Draft → InReview → Approved → InForce → Superseded` (and `Rejected`)
  lifecycle, identified-risk inventory with inherent/residual levels,
  `requiring_regulator_consultation()` query (GDPR Art 36), and supersedes
  chain. Maps to GDPR Art 35.
- `privacy_request_register` — DSAR / right-to-know / right-to-delete /
  rectification / portability / objection / automated-decision-review /
  opt-out tracking with `Received → Verified → InProgress → Fulfilled |
  Rejected | Withdrawn` lifecycle, statutory deadline tracking, and
  `overdue() / due_within(now, days)` queries. Maps to GDPR Art 15-22 and
  CCPA / CPRA.
- `encryption_inventory` — encryption-at-rest catalog: per-asset
  algorithm, key manager (CloudKms / Hsm / Byok / Application), key
  rotation history, `rotation_overdue()` and `audit_failures()` queries.
  Maps to NIST 800-53 SC-28, PCI 3.5, HIPAA §164.312(a)(2)(iv).
- `retention_register` — data retention policy catalog: classes with
  legal basis (Statutory / Contractual / BusinessInterest / Consent /
  LegalHold), disposition (HardDelete / CryptoShred / Anonymise /
  Aggregate / ArchiveColdStorage), category-to-class assignment table,
  annual-review tracking, and `unassigned_categories()` audit. Maps to
  GDPR Art 5(1)(e), HIPAA §164.530(j), SOX §802.

### Tests

- 88 new unit tests (dpia_register 24, privacy_request_register 19,
  encryption_inventory 21, retention_register 24).
- Cumulative sandbox-core lib: **2,994 tests / 0 failures / ~1.2s**.

### Prelude

- `Dpia`, `DpiaRegister`, `DpiaStage`, `DpiaEvent`, `DpiaRisk`,
  `DpiaLegalBasis`, `DpiaRiskLevel`
- `PrivacyRequest`, `PrivacyRequestRegister`, `PrivacyRequestEvent`,
  `PrivacyRequestStage`, `PrivacyRequestSubjectKind`, `PrivacyRightKind`
- `EncryptedAsset`, `EncryptionInventory`, `EncryptionAlgorithm`,
  `EncryptionDataClass`, `EncryptionRotationRecord`, `KeyManager`
- `RetentionRegister`, `RetentionPolicyClass` (collision-safe rename;
  `seal::RetentionClass` already in prelude), `RetentionBasis`,
  `RetentionDisposition`, `CategoryAssignment`

---

## [0.2.22] - 2026-05-08

Change & release management cluster: disaster recovery drills, service
catalog (developer portal), deployment calendar (change windows / freeze
periods), and structured customer release notes. Closes ITIL change
control, SOC2 CC8.1, and ISO 22301 audit gaps in one push.

### Added

- `disaster_recovery` — DR plan registry with tier (Tier1..Tier4), target
  RPO/RTO, drill cadence, drill history, and `drill_overdue` /
  `last_drill_met_targets` queries. Maps to SOC2 CC9.1, ISO 22301,
  NIST 800-34.
- `service_catalog` — internal developer portal: service ownership,
  on-call binding, repository, documentation links, compliance scope,
  SLO bindings, and `Proposed → Alpha → Beta → Ga → Deprecated → Retired`
  lifecycle. `missing_on_call()` flags live services with no on-call
  schedule.
- `deployment_calendar` — change windows, freezes, and maintenance
  windows with `is_deployable_at()` returning `Allowed | Blocked` plus
  the active freeze/window. Freezes always win; service-scoped freezes
  isolate to listed services.
- `release_notes` — structured per-version release log with
  `Preview/Beta/Ga/Deprecated/Removed` stage, Keep-a-Changelog categories,
  supersedes/superseded-by links, `since_version()` query, and Markdown
  rendering for changelog publication.

### Tests

- 89 new unit tests (disaster_recovery 22, service_catalog 22,
  deployment_calendar 20, release_notes 25).
- Cumulative sandbox-core lib: **2,906 tests / 0 failures / ~1.2s**.

### Prelude

- `DisasterRecoveryRegistry`, `DrPlan`, `DrTier`, `DrDrillKind`,
  `DrDrillOutcome`, `DrDrillRecord`
- `ServiceCatalog`, `ServiceEntry`, `ServiceLifecycleStage`,
  `ServiceComplianceScope`, `ServiceLink`, `SloBinding`
- `DeploymentCalendar`, `CalendarEntry`, `CalendarEntryKind`,
  `DeployabilityCheck`
- `ReleaseNotesRegistry`, `ReleaseNote`, `NoteEntry`, `NoteCategory`,
  `SupportStage`

---

## [0.2.21] - 2026-05-08

Operational-control cluster: secrets rotation, on-call schedules, and
vulnerability disclosure tracking. Closes a recurring SOC2/ISO27001
audit-finding cluster around credential lifecycle and incident readiness.

### Added

- `secrets_rotation` — credential rotation registry with per-secret max-age,
  rotation history, `due_for_rotation` query. Maps to NIST 800-53 IA-5,
  PCI 8.2.4, SOC2 CC6.1.
- `on_call_schedule` — named on-call schedules with primary/secondary roles,
  override shifts, and "who is on-call now" lookup. Maps to ISO 27001 A.6.1.1.
- `vulnerability_disclosure` — internal advisory registry with CVE/CVSS,
  Reported→UnderEmbargo→Disclosed→Resolved lifecycle, affected-component
  inventory, and chronological public-update log. Maps to ISO 29147 and
  NIST 800-53 SI-5.

### Tests

- 62 new unit tests (secrets_rotation 22, on_call_schedule 19,
  vulnerability_disclosure 21).
- Cumulative sandbox-core lib: **2,817 tests / 0 failures / ~1.2s**.
- Full workspace (excluding `aethelred-benchmarks`):
  **3,944 tests across 18 sections / 0 failures**.

### Prelude

- `RotationEvent`, `RotationOutcome`, `SecretKind`, `SecretRecord`,
  `SecretsRotationRegistry`
- `OnCallRegistry`, `Schedule`, `Shift`, `ShiftRole`
- `Advisory`, `AdvisorySeverity`, `AdvisoryStage`, `AdvisoryUpdate`,
  `AffectedComponent`, `VulnerabilityRegistry`

---

## [0.2.20] - 2026-05-08

Observability + governance cluster: log aggregation, customer dashboards,
content lifecycle, API version compatibility, and operator session tracking.

### Added

- `log_aggregation` — capacity-bounded log buffer with level filter and JSONL
  export. Underpins audit trails for non-seal events.
- `dashboard_widget` — tenant-scoped customer dashboards with widget kinds
  (`SingleStat`, `TimeSeries`, `Gauge`, `Table`, `List`, `Heatmap`), refresh
  policies, and grid layout.
- `content_archive` — content-lifecycle registry tracking
  Active↔Archived→Deleted→Restored with history and legal-transition
  validation.
- `api_versioning` — public-API lifecycle registry with
  Active→Deprecated→Sunset→Removed transitions, sunset-date enforcement, and
  per-request `check()` to enforce wire-compat fail-closed.
- `user_session` — operator session registry with MFA factor, login IP/UA,
  idle and absolute timeouts, sweep-based expiry, and Active→Expired/Revoked/
  LoggedOut lifecycle. Maps to SOC2 CC6.1, ISO 27001 A.9.4.

### Tests

- 118 new unit tests (log_aggregation 23, dashboard_widget 21,
  content_archive 20, api_versioning 26, user_session 28).
- Cumulative sandbox-core lib: **2,755 tests / 0 failures / ~1.2s**.

### Prelude

- `LogAggregator`, `LogEntry`, `LogLevel`
- `Dashboard`, `DashboardLayout`, `DashboardRegistry`, `RefreshPolicy`,
  `Widget`, `WidgetKind`
- `ContentArchive`, `ContentEntry`, `LifecycleStage`, `LifecycleTransition`
- `ApiVersionRegistry`, `CompatibilityCheck`, `CompatibilityKind`,
  `VersionEntry`, `VersionStage`, `api_now_rfc3339`
- `MfaFactor`, `SessionActivity`, `SessionState`, `UserSession`,
  `UserSessionRegistry`

---

## [0.2.19] - 2026-05-07

Continuity + governance cluster: multi-region replication, edge-node fleet,
sandbox cloning with redaction, change advisory boards, and operational
baselines.

### Added

- `multi_region_replication` — replication groups with primary failover,
  per-replica mode (`Sync`/`Async`/`CatchUp`/`Paused`), lag tracking, and
  `promote_to_primary` source/target swap.
- `edge_node_registry` — edge-fleet inventory with capacity, current load,
  status, sector-aware routing, and least-loaded selection.
- `sandbox_clone` — sandbox-clone jobs with `CloneScope` (full vs.
  config-only), `RedactionPolicy` (None/HashOnly/DropPii/Synthesize), and
  Pending→Running→Completed/Failed/Cancelled state machine.
- `change_advisory_board` — ITIL CAB workflow with weighted votes, quorum
  helpers, and Submitted→InReview→Approved/Rejected/Deferred→Implemented/
  Withdrawn lifecycle.
- `operational_baseline` — rolling baseline registry with mean/stddev/p50/p95/
  p99/min/max, FIFO window cap, z-score, and `is_anomalous()` helpers.

### Tests

- 120 new unit tests across the five modules.
- Cumulative sandbox-core lib: **2,637 tests / 0 failures**.

---

## Earlier versions

For the full history before v0.2.19 see git log on `crates/sandbox-core/`.
The crate began as `aethelred-sandbox::enterprise_sandboxes` and was extracted
into a workspace-style sandbox-core + 7 sector crates at v0.2.1.
