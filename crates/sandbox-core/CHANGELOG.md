# Aethelred Infinity Sandbox — Core Changelog

All notable changes to `aethelred-sandbox-core` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Each release lists the new tier-1 enterprise modules added, the cumulative
unit-test count, and the public surface that was wired through
`aethelred_sandbox_core::prelude::*`.

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
