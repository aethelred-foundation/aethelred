# Aethelred Validator Operations Guide (v1.0)

**Classification: CONFIDENTIAL - For FAB & DBS Infrastructure Teams Only**

**Document Version:** 1.0
**Last Updated:** 2024
**Contact:** security@aethelred.org | ops@aethelred.org

---

## Executive Summary

This document provides comprehensive operational guidance for running an Aethelred validator node. Adherence to these procedures is mandatory to:

1. **Prevent slashing** of staked assets (up to 50% penalty for double-signing)
2. **Ensure network security** through proper key management
3. **Maintain regulatory compliance** with ADGM/DFSA requirements
4. **Achieve 99.99% uptime** SLA commitments

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Hardware Requirements](#2-hardware-requirements)
3. [HSM Key Management](#3-hsm-key-management)
4. [Node Deployment](#4-node-deployment)
5. [Slashing Prevention](#5-slashing-prevention)
6. [Monitoring & Alerting](#6-monitoring--alerting)
7. [Disaster Recovery](#7-disaster-recovery)
8. [Security Procedures](#8-security-procedures)
9. [Emergency Contacts](#9-emergency-contacts)

---

## 1. Architecture Overview

### Recommended Deployment Topology

Your validator deployment MUST consist of three components:

```
 ┌─────────────────────────────────────────────────┐
 │ INTERNET │
 └─────────────────────────────────────────────────┘
 │
 ▼
 ┌────────────────────────────────────────────────────────┐
 │ SENTRY NODES (2+) │
 │ • Public-facing │
 │ • Absorbs DDoS attacks │
 │ • No signing keys │
 │ • Connects to P2P network │
 └────────────────────────────────────────────────────────┘
 │
 Private Network Only
 ▼
 ┌────────────────────────────────────────────────────────┐
 │ VALIDATOR NODE │
 │ • Private IP ONLY │
 │ • Connects ONLY to Sentry nodes │
 │ • HSM-protected signing keys │
 │ • Minimal attack surface │
 └────────────────────────────────────────────────────────┘
 │
 Separate Availability Zone
 ▼
 ┌────────────────────────────────────────────────────────┐
 │ FAILOVER NODE │
 │ • Cold standby │
 │ • Different AZ/Region │
 │ • HSM key access DISABLED by default │
 │ • Activated ONLY when Primary confirmed dead │
 └────────────────────────────────────────────────────────┘
```

### Network Isolation Requirements

| Component | Public IP | Private Network | HSM Access |
|-----------|-----------|-----------------|------------|
| Sentry Node | Required | Connected | None |
| Validator Node | NEVER | Private Only | Active |
| Failover Node | NEVER | Private Only | Disabled |

---

## 2. Hardware Requirements

### Validator Node Specifications

| Component | Minimum Spec | Recommended Spec | Notes |
|-----------|-------------|------------------|-------|
| **CPU** | AMD EPYC 7543 (32-core) | AMD EPYC 7763 (64-core) | Required for zkProof verification |
| **RAM** | 128 GB ECC DDR4 | 256 GB ECC DDR4 | Large mempool for AI compute blobs |
| **Storage** | 2TB NVMe SSD | 4TB NVMe SSD (RAID-1) | High IOPS for state DB |
| **Network** | 10 Gbps | 25 Gbps | Low latency to peers |
| **HSM** | AWS CloudHSM | Thales Luna PCIe | FIPS 140-2 Level 3 required |

### HSM Requirements

| HSM Model | Certification | Performance | Integration |
|-----------|--------------|-------------|-------------|
| **AWS CloudHSM** | FIPS 140-2 L3, PCI-DSS | 2,000+ signs/sec | Native |
| **Thales Luna Network HSM 7** | FIPS 140-2 L3, CC EAL4+ | 10,000+ signs/sec | PKCS#11 |
| **YubiHSM 2** | FIPS 140-2 L3 | 200 signs/sec | Development Only |

### Power Requirements

- **Redundant PSU**: 2x 1200W minimum
- **UPS**: 30+ minutes runtime
- **Generator**: For datacenter deployments

---

## 3. HSM Key Management

### Initial Key Generation

**CRITICAL**: Keys must be generated INSIDE the HSM. Never import externally generated keys.

```bash
#!/bin/bash
# generate_validator_key.sh
# Run this ONCE during initial setup

# Connect to HSM
pkcs11-tool --module /opt/cloudhsm/lib/libcloudhsm_pkcs11.so \
 --login --pin "$HSM_PIN" \
 --keypairgen \
 --key-type EC:secp256k1 \
 --label "aethelred-validator-key" \
 --id 01

# Verify key was created
pkcs11-tool --module /opt/cloudhsm/lib/libcloudhsm_pkcs11.so \
 --login --pin "$HSM_PIN" \
 --list-objects

# Export PUBLIC key only (private key cannot be exported)
pkcs11-tool --module /opt/cloudhsm/lib/libcloudhsm_pkcs11.so \
 --login --pin "$HSM_PIN" \
 --read-object --type pubkey --label "aethelred-validator-key" \
 -o validator_public_key.der
```

### Key Backup Procedure

HSM keys are backed up using **wrapped key export** (encrypted with master key):

```bash
# AWS CloudHSM key backup
aws cloudhsmv2 create-backup \
 --cluster-id cluster-xxxxx \
 --destination-backup-id "validator-backup-$(date +%Y%m%d)"
```

**Storage Requirements:**
- Backup encrypted with separate KMS key
- Store in geographically separate region
- Minimum 2 copies in different secure facilities
- Annual key backup verification

### Key Rotation Schedule

| Key Type | Rotation Frequency | Procedure |
|----------|-------------------|-----------|
| Validator Signing Key | Never (permanent) | Only on compromise |
| Session Keys | Every 24 hours | Automatic |
| TLS Certificates | Every 90 days | Manual with approval |

---

## 4. Node Deployment

### Pre-Deployment Checklist

- [ ] HSM initialized and key generated
- [ ] Network firewall rules configured
- [ ] Sentry nodes operational (2 minimum)
- [ ] Monitoring agents installed
- [ ] Backup procedures tested
- [ ] Emergency contacts verified

### Installation

```bash
#!/bin/bash
# install_validator.sh

# 1. Install dependencies
apt-get update && apt-get install -y \
 docker.io \
 jq \
 prometheus-node-exporter

# 2. Create directories
mkdir -p /data/aethelred/{config,data,keys}
chmod 700 /data/aethelred/keys

# 3. Pull the Aethelred node image
docker pull aethelred/node:mainnet-v1.0.0

# 4. Create config
cat > /data/aethelred/config/config.toml << 'EOF'
[base]
role = "validator"
moniker = "FAB-Validator-01"

[consensus]
block_time = "6s"
timeout_propose = "3s"
timeout_prevote = "1s"
timeout_precommit = "1s"

[p2p]
seeds = []
persistent_peers = "sentry-1-id@sentry-1.internal:26656,sentry-2-id@sentry-2.internal:26656"
pex = false
addr_book_strict = true

[hsm]
enabled = true
module_path = "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so"
# Legacy single-key label (no rotation)
key_label = "aethelred-validator-key"
# Versioned rotation (recommended for production):
# key_label_prefix = "aethelred-validator-key"
# key_version = 1

[telemetry]
enabled = true
prometheus_listen_addr = "127.0.0.1:26660"
EOF

# 5. Start the node
docker run -d \
 --name aethelred-validator \
 --restart unless-stopped \
 --net host \
 -v /data/aethelred:/data \
 -v /opt/cloudhsm:/opt/cloudhsm:ro \
 --device /dev/cloudhsm \
 aethelred/node:mainnet-v1.0.0 \
 start --config /data/config/config.toml
```

### Verify Node Status

```bash
# Check sync status
aethelredd status | jq '.sync_info'

# Check validator is signing
aethelredd query staking validator $(aethelredd keys show validator -a --bech val)

# Check HSM connectivity
aethelredd admin hsm-status
```

---

## 5. Slashing Prevention

### Critical Rules

IMPORTANT: **Double Signing = 50% Stake Slash + Permanent Jail**

Double signing occurs when the same validator key signs two different blocks at the same height. This is the most severe slashing offense.

**Prevention Measures:**

1. **NEVER run two validators with the same key simultaneously**
2. **NEVER copy the HSM session to another machine**
3. **NEVER run the failover before confirming primary is dead**

### Failover Procedure

```bash
#!/bin/bash
# promote_failover.sh
# RUN ONLY AFTER CONFIRMING PRIMARY IS DEAD

set -e

# 1. Verify primary is truly unreachable (wait 5 minutes)
echo "Checking primary node status..."
for i in {1..10}; do
 if ping -c 1 primary-validator.internal; then
 echo "PRIMARY IS STILL ALIVE! Aborting failover."
 exit 1
 fi
 sleep 30
done

# 2. Check with multiple sources that primary is not signing
LAST_SIGNED=$(curl -s https://api.aethelred.org/validators/$VALIDATOR_ADDR/last_signed)
CURRENT_HEIGHT=$(curl -s https://api.aethelred.org/status | jq .height)

if [ $((CURRENT_HEIGHT - LAST_SIGNED)) -lt 100 ]; then
 echo "PRIMARY MAY STILL BE ACTIVE! Last signed $LAST_SIGNED, current $CURRENT_HEIGHT"
 echo "Waiting for 100 blocks of inactivity..."
 exit 1
fi

# 3. Disable primary HSM session (if reachable)
ssh primary-validator "pkcs11-tool --logout || true"

# 4. Enable failover HSM session
echo "Activating failover HSM..."
pkcs11-tool --module /opt/cloudhsm/lib/libcloudhsm_pkcs11.so \
 --login --pin "$HSM_PIN"

# 5. Start failover validator
docker start aethelred-validator

# 6. Notify operations team
curl -X POST https://hooks.slack.com/services/xxx \
 -d '{"text":"IMPORTANT: FAILOVER ACTIVATED for validator '$VALIDATOR_ADDR'"}'

echo "Failover complete. Monitor for successful block signing."
```

### Slashing Conditions Reference

| Offense | Penalty | Jail Duration | Recovery |
|---------|---------|---------------|----------|
| Double Signing | 50% slash | Permanent | Impossible |
| Downtime (>500 blocks) | 0.01% slash | 10 minutes | Automatic |
| Byzantine Behavior | 5% slash | 1 week | Governance vote |

---

## 6. Monitoring & Alerting

### Required Metrics

```yaml
# prometheus-alerts.yml
groups:
 - name: aethelred-validator
 rules:
 # Block signing stopped
 - alert: ValidatorNotSigning
 expr: increase(aethelred_blocks_signed_total[5m]) == 0
 for: 5m
 labels:
 severity: critical
 annotations:
 summary: "Validator has stopped signing blocks"

 # HSM connectivity lost
 - alert: HSMConnectionLost
 expr: aethelred_hsm_connected == 0
 for: 1m
 labels:
 severity: critical
 annotations:
 summary: "HSM connection lost - signing disabled"

 # Approaching slashing threshold
 - alert: MissedBlocksWarning
 expr: aethelred_consecutive_missed_blocks > 100
 for: 1m
 labels:
 severity: warning
 annotations:
 summary: "Approaching slashing threshold (500 blocks)"

 # Disk space
 - alert: DiskSpaceLow
 expr: node_filesystem_avail_bytes{mountpoint="/data"} < 50*1024*1024*1024
 for: 5m
 labels:
 severity: warning
 annotations:
 summary: "Less than 50GB disk space remaining"
```

### Dashboard URLs

- **Grafana**: https://monitoring.aethelred.internal:3000
- **Prometheus**: https://monitoring.aethelred.internal:9090
- **Alertmanager**: https://monitoring.aethelred.internal:9093

---

## 7. Disaster Recovery

### Recovery Time Objectives

| Scenario | RTO | RPO | Procedure |
|----------|-----|-----|-----------|
| Node crash | < 5 min | 0 | Automatic restart |
| Datacenter outage | < 15 min | 0 | Failover activation |
| HSM failure | < 1 hour | 0 | HSM cluster failover |
| Region outage | < 30 min | 0 | Cross-region DR |

### Backup Verification (Monthly)

```bash
#!/bin/bash
# verify_backups.sh

# 1. Test state snapshot restore
aethelredd snapshot restore --dry-run /backups/latest.tar.gz

# 2. Verify HSM backup can decrypt
aws cloudhsmv2 describe-backups --backup-id latest

# 3. Test failover node can start
ssh failover "docker run --rm aethelred/node:latest version"

# 4. Log verification results
echo "Backup verification completed: $(date)" >> /var/log/backup-verify.log
```

---

## 8. Security Procedures

### Access Control

| Role | SSH Access | HSM Access | Console Access |
|------|------------|------------|----------------|
| Validator Operator | Yes | Yes | Yes |
| NOC Engineer | Yes | No | Yes (read-only) |
| Auditor | No | No | Yes (read-only) |

### Security Checklist (Weekly)

- [ ] Review SSH access logs
- [ ] Verify firewall rules unchanged
- [ ] Check HSM audit logs
- [ ] Confirm backup integrity
- [ ] Update security patches (staging first)
- [ ] Rotate session tokens

### Incident Response

1. **Detection**: Automated alert received
2. **Triage**: Assess severity (P1-P4)
3. **Containment**: Isolate affected systems
4. **Eradication**: Remove threat
5. **Recovery**: Restore service
6. **Post-mortem**: Document and improve

---

## 9. Emergency Contacts

### Aethelred Support

| Contact | Availability | Response Time |
|---------|--------------|---------------|
| **NOC Hotline** | 24/7 | Immediate |
| **+971-50-XXX-XXXX** | | |
| **Security Incident** | 24/7 | < 15 min |
| **security@aethelred.org** | | |
| **Slack: #validators-emergency** | 24/7 | < 5 min |

### Escalation Path

```
L1: NOC Engineer
 ↓ (15 min no response)
L2: Platform Lead
 ↓ (30 min no resolution)
L3: VP Engineering
 ↓ (Critical incident)
L4: CTO / CEO
```

### Bank IT Security Teams

| Organization | Contact | Phone |
|--------------|---------|-------|
| FAB IT Security | [REDACTED] | [REDACTED] |
| DBS IT Security | [REDACTED] | [REDACTED] |

---

## Appendix A: Command Reference

```bash
# Check node status
aethelredd status

# View logs
docker logs -f aethelred-validator

# Emergency stop
docker stop aethelred-validator

# Check HSM status
aethelredd admin hsm-status

# Export validator address
aethelredd keys show validator -a --bech val

# Check staking status
aethelredd query staking validator $VAL_ADDR

# Unjail (after downtime slashing)
aethelredd tx slashing unjail --from validator --gas auto
```

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-XX-XX | Aethelred Team | Initial release |

---

**END OF DOCUMENT**

*This document contains confidential information. Do not distribute outside authorized personnel.*
