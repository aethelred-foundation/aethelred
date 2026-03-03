# Aethelred Operations Runbook (v1.0)

**Audience:** SRE, DevOps, Security, Validator Operators
**Scope:** Validator nodes, sentry nodes, off-chain verification services, monitoring, upgrades, incident response
**Last Updated:** 2026-02-07

---

## 0. Purpose

This runbook provides operational procedures to deploy, monitor, maintain, and recover Aethelred infrastructure in production. It complements `docs/VALIDATOR_RUNBOOK.md` and focuses on day-2 operations.

---

## 1. System Components

1. Validator node (Cosmos SDK app + CometBFT)
2. Sentry nodes (public P2P edge)
3. Off-chain verification services
4. TEE worker service
5. zkML prover/verifier service
6. Metrics and logging stack

---

## 2. Environment Conventions

1. `dev` for local or single-node testing
2. `testnet` for multi-node integration
3. `mainnet` for production

---

## 3. Preflight Checklist

1. Confirm key material and HSM access are configured.
2. Validate env vars for TEE and zkML endpoints.
3. Confirm network routing for sentry <-> validator.
4. Confirm storage capacity and snapshot strategy.
5. Verify monitoring endpoints are reachable.
6. Verify `/health/aethelred` reports healthy for all components.

---

## 4. Deployment Procedure

### 4.1 Node Installation

1. Install system dependencies (container runtime or binary toolchain).
2. Create data directories and permissions.
3. Configure node settings in config files and env vars.
4. Start the node and verify it begins to sync.

### 4.2 Verification Services

1. Deploy TEE worker(s) behind private endpoints.
2. Deploy zkML prover/verifier services.
3. Confirm attestation verifier endpoint, if used.
4. Validate readiness checks pass in production mode.

---

## 5. Runtime Health Checks

### 5.1 Health Endpoint

Call:
- `GET /health/aethelred`

Expected:
- `status=healthy`
- All components `healthy` or `simulated` (dev only)

### 5.2 Metrics Endpoint

Call:
- `GET /metrics/aethelred`

Expected:
- Orchestrator metrics present
- PoUW module metrics present
- Circuit breaker metrics present

---

## 6. Monitoring and Alerting

### 6.1 Core Alerts

1. Node not producing blocks
2. Validator signing lag or missed blocks
3. TEE or zkML verification failures above baseline
4. Circuit breakers in `open` or `half_open`
5. Low disk space or DB errors

### 6.2 Suggested SLOs

1. Block production availability >= 99.9%
2. Verification pipeline success rate >= 99%
3. Median verification latency <= 3s

---

## 7. Incident Response Playbooks

### 7.1 Node Down

1. Confirm sentry nodes can still reach peers.
2. Check validator node process status and logs.
3. If DB corruption is suspected, stop node and restore from snapshot.
4. If hardware failure, promote cold standby.

### 7.2 High Missed Blocks / Slashing Risk

1. Check validator performance metrics.
2. Verify HSM connectivity and signing latency.
3. Inspect network latency to sentry nodes.
4. Reduce load on the validator or failover.

### 7.3 TEE / zkML Outage

1. Check `/health` for TEE and orchestrator status.
2. Validate endpoints and circuit breaker states.
3. If production and `AllowSimulated=false`, treat as SEV-1.
4. Restore service or failover to a healthy region.

### 7.4 Verification Mismatch Spike

1. Inspect consensus logs for mismatches.
2. Validate model registry integrity and hash matching.
3. Pause affected workloads until resolution.
4. Open security investigation if mismatch indicates tampering.

---

## 8. Backup and Recovery

### 8.1 Backup Policy

1. Full state snapshot daily.
2. Incremental snapshots hourly.
3. HSM key backups per vendor procedure.
4. Store backups in at least two regions.

### 8.2 Restore Procedure

1. Stop the node.
2. Restore from latest good snapshot.
3. Verify DB integrity and replay blocks.
4. Bring node online and monitor catch-up.

---

## 9. Upgrades and Migrations

### 9.1 Upgrade Checklist

1. Review module version and migration handlers.
2. Create full snapshot and verify restore procedure.
3. Deploy binaries to standby nodes first.
4. Execute upgrade on testnet before mainnet.
5. Verify `/health/aethelred` and metrics after upgrade.

### 9.2 Rollback Strategy

1. Stop the upgraded node.
2. Restore previous version binaries.
3. Restore from pre-upgrade snapshot.
4. Rejoin the network and verify consensus.

---

## 10. Security Operations

1. Apply OS security patches monthly.
2. Rotate TLS certificates every 90 days.
3. Audit access to key management systems.
4. Review governance parameter changes weekly.

---

## 11. Logging and Audit

1. Centralize logs from validator, sentry, and verification services.
2. Retain logs for at least 90 days.
3. Audit events should include slashing and governance changes.

---

## 12. Capacity Planning

1. Track CPU, memory, and disk IO usage trends.
2. Scale verifier services independently of validators.
3. Add storage before 80% capacity.

---

## 13. References

1. `docs/VALIDATOR_RUNBOOK.md`
2. `docs/architecture.md`
3. `docs/operations/geographic-redundancy.md`
4. `docs/operations/enterprise-infrastructure.md`
5. `docs/operations/secret-management.md`
6. `docs/operations/load-testing.md`
