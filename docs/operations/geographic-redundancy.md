# Aethelred Geographic Redundancy & High Availability

## Executive Summary

This document describes the enterprise-grade geographic redundancy architecture for Aethelred validators, ensuring 99.99% uptime and compliance with Abu Dhabi SWF requirements for mission-critical financial AI verification infrastructure.

## Architecture Overview

```
                         ┌─────────────────────────────────────┐
                         │         GLOBAL LOAD BALANCER        │
                         │    (AWS Route 53 / Cloudflare)      │
                         └──────────────┬──────────────────────┘
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           │                            │                            │
           ▼                            ▼                            ▼
┌──────────────────────┐   ┌──────────────────────┐   ┌──────────────────────┐
│    REGION: UAE       │   │   REGION: EUROPE     │   │   REGION: ASIA       │
│   (Abu Dhabi/Dubai)  │   │  (Frankfurt/London)  │   │  (Singapore/Tokyo)   │
│                      │   │                      │   │                      │
│ ┌──────────────────┐ │   │ ┌──────────────────┐ │   │ ┌──────────────────┐ │
│ │  AZ-1: Primary   │ │   │ │  AZ-1: Primary   │ │   │ │  AZ-1: Primary   │ │
│ │  ┌────────────┐  │ │   │ │  ┌────────────┐  │ │   │ │  ┌────────────┐  │ │
│ │  │ Validator  │  │ │   │ │  │ Validator  │  │ │   │ │  │ Validator  │  │ │
│ │  │   + TEE    │  │ │   │ │  │   + TEE    │  │ │   │ │  │   + TEE    │  │ │
│ │  └────────────┘  │ │   │ │  └────────────┘  │ │   │ │  └────────────┘  │ │
│ │  ┌────────────┐  │ │   │ │  ┌────────────┐  │ │   │ │  ┌────────────┐  │ │
│ │  │    HSM     │  │ │   │ │  │    HSM     │  │ │   │ │  │    HSM     │  │ │
│ │  └────────────┘  │ │   │ │  └────────────┘  │ │   │ │  └────────────┘  │ │
│ └──────────────────┘ │   │ └──────────────────┘ │   │ └──────────────────┘ │
│                      │   │                      │   │                      │
│ ┌──────────────────┐ │   │ ┌──────────────────┐ │   │ ┌──────────────────┐ │
│ │  AZ-2: Standby   │ │   │ │  AZ-2: Standby   │ │   │ │  AZ-2: Standby   │ │
│ │  (Hot Failover)  │ │   │ │  (Hot Failover)  │ │   │ │  (Hot Failover)  │ │
│ └──────────────────┘ │   │ └──────────────────┘ │   │ └──────────────────┘ │
│                      │   │                      │   │                      │
│ ┌──────────────────┐ │   │ ┌──────────────────┐ │   │ ┌──────────────────┐ │
│ │  AZ-3: Witness   │ │   │ │  AZ-3: Witness   │ │   │ │  AZ-3: Witness   │ │
│ │ (Quorum Voting)  │ │   │ │ (Quorum Voting)  │ │   │ │ (Quorum Voting)  │ │
│ └──────────────────┘ │   │ └──────────────────┘ │   │ └──────────────────┘ │
└──────────────────────┘   └──────────────────────┘   └──────────────────────┘
           │                            │                            │
           └────────────────────────────┼────────────────────────────┘
                                        │
                         ┌──────────────▼──────────────────────┐
                         │     CROSS-REGION REPLICATION        │
                         │   (State Sync & P2P Networking)     │
                         └─────────────────────────────────────┘
```

## Regional Deployment Strategy

### Primary Regions

| Region | Location | Purpose | SLA |
|--------|----------|---------|-----|
| **UAE** | Abu Dhabi (me-south-1) | Primary for MENA | 99.99% |
| **Europe** | Frankfurt (eu-central-1) | EU compliance | 99.99% |
| **Asia** | Singapore (ap-southeast-1) | APAC coverage | 99.99% |

### Availability Zone Distribution

Each region deploys validators across 3 availability zones:

1. **Primary AZ**: Active validator with HSM
2. **Standby AZ**: Hot standby with automatic failover
3. **Witness AZ**: Consensus witness node

## Infrastructure Requirements

### Validator Node Specifications

```yaml
# Primary Validator
validator_primary:
  instance_type: m6i.4xlarge    # 16 vCPU, 64GB RAM
  storage:
    root: 500GB gp3 (16000 IOPS)
    data: 2TB io2 (64000 IOPS)
  network: 25 Gbps
  tee: AWS Nitro Enclave (8 vCPU, 32GB)

# Standby Validator
validator_standby:
  instance_type: m6i.2xlarge    # 8 vCPU, 32GB RAM
  storage:
    root: 500GB gp3
    data: 2TB gp3
  state_sync: real-time

# Witness Node
witness_node:
  instance_type: m6i.xlarge     # 4 vCPU, 16GB RAM
  storage:
    root: 200GB gp3
    data: 1TB gp3
  role: consensus_observer
```

### HSM Configuration

```yaml
hsm_cluster:
  type: AWS CloudHSM
  availability_zones: 3
  replication: synchronous
  backup:
    frequency: hourly
    retention: 90_days
    cross_region: true

  key_management:
    validator_key:
      algorithm: ECDSA P-256
      extractable: false
      backup_wrapped: true
    pqc_key:
      algorithm: Dilithium3
      extractable: false
      hsm_only: true
```

## Failover Procedures

### Automatic Failover

The system implements three levels of automatic failover:

#### Level 1: Intra-AZ Failover (< 30 seconds)
- Process crash detection and restart
- TEE enclave recovery
- Connection pool refresh

```go
// Automatic health check and restart
type HealthMonitor struct {
    CheckInterval   time.Duration // 5 seconds
    FailureThreshold int          // 3 consecutive failures
    RestartDelay    time.Duration // 10 seconds
}
```

#### Level 2: Cross-AZ Failover (< 2 minutes)
- Standby promotion when primary is unreachable
- HSM session transfer
- DNS/Load balancer update

```yaml
failover_config:
  detection_time: 30s
  promotion_time: 60s
  total_rto: 120s
  rpo: 0 (zero data loss)

triggers:
  - health_check_failure: 3
  - network_partition: 60s
  - hsm_disconnection: 30s
  - tee_attestation_failure: immediate
```

#### Level 3: Cross-Region Failover (< 15 minutes)
- Disaster recovery activation
- Global DNS failover
- State reconstruction from replicas

### Manual Failover Procedures

#### Planned Maintenance Failover

```bash
#!/bin/bash
# graceful_failover.sh - Planned maintenance failover

# 1. Signal intention to network
aethelredd tx staking signal-maintenance \
  --validator $VALIDATOR_ADDR \
  --duration 1h \
  --from operator

# 2. Wait for current block to finalize
aethelredd query consensus wait-finalized

# 3. Stop signing (let standby take over)
aethelredd admin pause-signing

# 4. Verify standby is active
aethelredd query staking validator-status $STANDBY_ADDR

# 5. Perform maintenance
# ... maintenance tasks ...

# 6. Rejoin as standby
aethelredd admin join-standby
```

#### Emergency Failover

```bash
#!/bin/bash
# emergency_failover.sh - Emergency recovery

# 1. Force standby promotion
ssh standby-node "aethelredd admin force-promote --emergency"

# 2. Update DNS immediately
aws route53 change-resource-record-sets \
  --hosted-zone-id $ZONE_ID \
  --change-batch file://failover-dns.json

# 3. Notify operations team
./alert.sh CRITICAL "Emergency failover executed"

# 4. Post-failover diagnostics
aethelredd admin diagnostic-report --output /var/log/aethelred/failover-report.json
```

## State Replication

### Real-time State Sync

```yaml
state_sync:
  mode: streaming
  protocol: CometBFT State Sync + Custom Extensions

  # Intra-region (same region, different AZ)
  intra_region:
    latency_target: < 10ms
    sync_interval: every_block
    full_sync: every_100_blocks

  # Cross-region
  cross_region:
    latency_target: < 100ms
    sync_interval: every_block
    full_sync: every_1000_blocks
    compression: lz4
    encryption: TLS 1.3

  # Critical state components
  sync_components:
    - validator_state
    - pending_jobs
    - vote_extensions
    - digital_seals
    - consensus_state
```

### Backup Strategy

| Data Type | Frequency | Retention | Storage |
|-----------|-----------|-----------|---------|
| Full State | Daily | 30 days | S3 Glacier Deep Archive |
| Incremental | Hourly | 7 days | S3 Standard-IA |
| Transaction Log | Real-time | 90 days | S3 Standard |
| HSM Keys | On Change | Forever | HSM Backup + Vault |
| Configuration | On Change | Forever | Git + Vault |

## Network Architecture

### P2P Topology

```
┌─────────────────────────────────────────────────────────────────────┐
│                        MESH NETWORK TOPOLOGY                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│    UAE Validators ◄──────► Europe Validators ◄──────► Asia Validators│
│         │                       │                          │         │
│         │                       │                          │         │
│         ▼                       ▼                          ▼         │
│    ┌─────────┐             ┌─────────┐              ┌─────────┐     │
│    │ Sentry  │◄───────────►│ Sentry  │◄────────────►│ Sentry  │     │
│    │  Nodes  │             │  Nodes  │              │  Nodes  │     │
│    └─────────┘             └─────────┘              └─────────┘     │
│         │                       │                          │         │
│         └───────────────────────┼──────────────────────────┘         │
│                                 │                                    │
│                         ┌───────▼───────┐                           │
│                         │  Public P2P   │                           │
│                         │   Network     │                           │
│                         └───────────────┘                           │
└─────────────────────────────────────────────────────────────────────┘
```

### Network Security

```yaml
network_security:
  # Validator-to-Validator
  validator_mesh:
    protocol: NOISE
    authentication: mutual_tls
    encryption: ChaCha20-Poly1305
    key_rotation: daily

  # Sentry Layer
  sentry_nodes:
    per_region: 3
    ddos_protection: AWS Shield Advanced
    rate_limiting:
      connections_per_ip: 10
      messages_per_second: 100

  # Firewall Rules
  firewall:
    p2p_port: 26656
    rpc_port: 26657 (internal only)
    grpc_port: 9090 (internal only)
    prometheus_port: 26660 (internal only)
```

## Monitoring & Alerting

### Metrics Collection

```yaml
monitoring:
  prometheus:
    scrape_interval: 15s
    retention: 30d
    federation: cross_region

  metrics:
    - validator_uptime
    - block_height
    - consensus_round_time
    - vote_extension_latency
    - tee_attestation_status
    - hsm_health
    - network_peers
    - state_sync_lag

  dashboards:
    - global_overview
    - regional_health
    - validator_performance
    - security_events
```

### Alert Thresholds

| Metric | Warning | Critical | Action |
|--------|---------|----------|--------|
| Block Height Lag | > 3 blocks | > 10 blocks | Investigate sync |
| Consensus Round Time | > 10s | > 30s | Check network |
| Vote Extension Miss | 1% | 5% | Check validator |
| HSM Response Time | > 100ms | > 500ms | Check HSM cluster |
| TEE Attestation Fail | 1 | 3 consecutive | Restart enclave |
| Network Peers | < 5 | < 3 | Check connectivity |
| State Sync Lag | > 1 min | > 5 min | Trigger resync |

### Incident Response

```
┌─────────────────────────────────────────────────────────────────┐
│                    INCIDENT RESPONSE WORKFLOW                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  DETECTION (< 1 min)                                            │
│      │                                                          │
│      ▼                                                          │
│  CLASSIFICATION                                                 │
│      │                                                          │
│      ├── P1 (Critical): < 15 min response                       │
│      │       - Total validator outage                           │
│      │       - HSM compromise                                   │
│      │       - Security breach                                  │
│      │                                                          │
│      ├── P2 (High): < 30 min response                          │
│      │       - Regional outage                                  │
│      │       - Consensus failure                                │
│      │       - Performance degradation > 50%                    │
│      │                                                          │
│      ├── P3 (Medium): < 2 hour response                        │
│      │       - Single AZ failure                                │
│      │       - Non-critical service degradation                 │
│      │                                                          │
│      └── P4 (Low): < 24 hour response                          │
│              - Monitoring gaps                                  │
│              - Documentation updates                            │
│                                                                  │
│  RESOLUTION & POST-MORTEM                                       │
│      - Root cause analysis                                      │
│      - Remediation implementation                               │
│      - Documentation update                                     │
│      - Stakeholder communication                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Compliance Considerations

### Data Residency

```yaml
data_residency:
  uae_region:
    # Abu Dhabi Global Market (ADGM) requirements
    data_types:
      - compute_job_metadata
      - verification_results
      - audit_logs
    storage_location: UAE only
    encryption: AES-256-GCM
    key_location: UAE HSM

  cross_border:
    # Data that can be replicated globally
    data_types:
      - blockchain_state
      - consensus_messages
      - public_proofs
    anonymization: required
    consent: not_required (public data)
```

### Audit Requirements

```yaml
audit_logging:
  retention: 7_years
  immutability: write_once_read_many
  storage: S3 Object Lock (Governance Mode)

  events:
    - validator_actions
    - key_operations
    - access_attempts
    - configuration_changes
    - failover_events

  format: JSON Lines (structured)
  encryption: at_rest_and_in_transit
  integrity: SHA-256 chain
```

## Disaster Recovery

### Recovery Time Objectives (RTO)

| Scenario | RTO | RPO | Procedure |
|----------|-----|-----|-----------|
| Single Node Failure | < 30 sec | 0 | Automatic failover |
| Single AZ Failure | < 2 min | 0 | Cross-AZ failover |
| Regional Failure | < 15 min | < 1 block | Cross-region failover |
| Global Outage | < 1 hour | < 10 blocks | Full DR activation |
| HSM Compromise | < 4 hours | Key rotation | Emergency key rotation |

### DR Runbook

```bash
#!/bin/bash
# disaster_recovery.sh - Full DR activation

set -e

echo "=== AETHELRED DISASTER RECOVERY ==="

# 1. Assess situation
echo "Step 1: Assessing current state..."
./assess_regional_health.sh

# 2. Activate DR region
echo "Step 2: Activating DR region..."
./activate_dr_region.sh --region $DR_REGION

# 3. Restore state from backup
echo "Step 3: Restoring state..."
./restore_state.sh \
  --source s3://$BACKUP_BUCKET/latest \
  --target $DR_REGION

# 4. Verify HSM connectivity
echo "Step 4: Verifying HSM..."
./verify_hsm.sh --region $DR_REGION

# 5. Update DNS
echo "Step 5: Updating DNS..."
./update_dns.sh --primary $DR_REGION

# 6. Notify network
echo "Step 6: Broadcasting recovery..."
aethelredd tx staking announce-recovery \
  --from operator \
  --region $DR_REGION

# 7. Verify consensus participation
echo "Step 7: Verifying consensus..."
./verify_consensus.sh --timeout 5m

echo "=== DR ACTIVATION COMPLETE ==="
```

## Cost Optimization

### Resource Allocation

```yaml
cost_optimization:
  # Reserved instances for predictable workloads
  reserved_capacity:
    primary_validators: 1_year_reserved
    standby_validators: on_demand_with_savings_plan

  # Auto-scaling for burst capacity
  auto_scaling:
    sentry_nodes:
      min: 3
      max: 10
      target_cpu: 60%

  # Storage tiering
  storage_tiering:
    hot_data: S3 Standard (last 7 days)
    warm_data: S3 Standard-IA (7-30 days)
    cold_data: S3 Glacier (30+ days)
    archive: S3 Glacier Deep Archive (1+ year)
```

### Estimated Monthly Costs

| Component | UAE | Europe | Asia | Total |
|-----------|-----|--------|------|-------|
| Validators (3 per region) | $8,000 | $7,500 | $7,000 | $22,500 |
| HSM Cluster | $3,500 | $3,500 | $3,500 | $10,500 |
| Storage | $2,000 | $2,000 | $2,000 | $6,000 |
| Network Transfer | $1,500 | $1,500 | $1,500 | $4,500 |
| Monitoring | $500 | $500 | $500 | $1,500 |
| **Total** | **$15,500** | **$15,000** | **$14,500** | **$45,000** |

## Appendix

### Configuration Templates

#### Terraform Module (AWS)

```hcl
module "aethelred_validator" {
  source = "./modules/validator"

  region     = "me-south-1"
  azs        = ["me-south-1a", "me-south-1b", "me-south-1c"]

  validator_config = {
    instance_type = "m6i.4xlarge"
    enclave_cpu   = 8
    enclave_memory = 32768
  }

  hsm_config = {
    type = "cloudhsm"
    cluster_size = 3
  }

  network_config = {
    vpc_cidr = "10.0.0.0/16"
    enable_nat = true
    enable_vpn = true
  }

  monitoring_config = {
    enable_prometheus = true
    enable_grafana    = true
    retention_days    = 30
  }
}
```

### Contact Information

- **Operations Team**: ops@aethelred.io
- **Security Team**: security@aethelred.io
- **On-Call Rotation**: PagerDuty (aethelred-validators)
- **Escalation Path**: DevOps → Platform Lead → CTO

---

*Document Version: 1.0*
*Last Updated: 2024*
*Classification: Internal - Operations*
