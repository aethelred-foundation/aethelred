# Hardware Security Module (HSM) Requirements

## Production Key Management for Aethelred Validators

**Version:** 1.0.0
**Classification:** Enterprise Security
**Last Updated:** 2024

---

## Executive Summary

This document outlines the Hardware Security Module (HSM) requirements for production deployments of Aethelred validators. Proper HSM integration is **mandatory** for mainnet validators handling institutional-grade AI verification workloads.

---

## Table of Contents

1. [Overview](#overview)
2. [Supported HSM Vendors](#supported-hsm-vendors)
3. [Security Requirements](#security-requirements)
4. [Key Types and Hierarchy](#key-types-and-hierarchy)
5. [Integration Architecture](#integration-architecture)
6. [Configuration Guide](#configuration-guide)
7. [Operational Procedures](#operational-procedures)
8. [Compliance and Auditing](#compliance-and-auditing)
9. [Disaster Recovery](#disaster-recovery)

---

## Overview

### Why HSMs are Required

Aethelred validators handle cryptographically sensitive operations including:

- **Consensus Signing**: Block proposals and vote extensions
- **Hybrid Signatures**: ECDSA + Dilithium3 post-quantum signatures
- **TEE Key Management**: Enclave sealing and attestation keys
- **Bridge Operations**: Cross-chain transaction signing

**Without HSM protection, private keys are vulnerable to:**
- Memory extraction attacks
- Side-channel attacks
- Insider threats
- Cold boot attacks
- Firmware-level compromises

### Security Levels

| Deployment Type | HSM Requirement | Minimum Certification |
|-----------------|-----------------|----------------------|
| Development | Not Required | N/A |
| Testnet | Recommended | FIPS 140-2 Level 2 |
| Mainnet (Individual) | Required | FIPS 140-2 Level 3 |
| Mainnet (Institutional) | Required | FIPS 140-3 Level 3 |
| Sovereign Deployments | Required | Common Criteria EAL4+ |

---

## Supported HSM Vendors

### Tier 1: Fully Certified

| Vendor | Model | Certification | Integration Status |
|--------|-------|---------------|-------------------|
| Thales | Luna Network HSM 7 | FIPS 140-3 Level 3 | ✅ Production Ready |
| Thales | Luna Cloud HSM | FIPS 140-2 Level 3 | ✅ Production Ready |
| nCipher/Entrust | nShield Connect XC | FIPS 140-2 Level 3 | ✅ Production Ready |
| AWS | CloudHSM | FIPS 140-2 Level 3 | ✅ Production Ready |
| Azure | Dedicated HSM | FIPS 140-2 Level 3 | ✅ Production Ready |
| GCP | Cloud HSM | FIPS 140-2 Level 3 | ✅ Production Ready |
| Yubico | YubiHSM 2 | FIPS 140-2 Level 3 | ✅ Production Ready |

### Tier 2: Community Supported

| Vendor | Model | Notes |
|--------|-------|-------|
| SoftHSM | v2.x | Development/Testing Only |
| Hashicorp Vault | Enterprise | With Transit Secrets Engine |
| Fortanix | SDKMS | Runtime Encryption |

---

## Security Requirements

### Cryptographic Requirements

```yaml
# Minimum cryptographic capabilities
cryptographic_requirements:
  algorithms:
    signing:
      - ECDSA (secp256k1)       # Classical consensus
      - Ed25519                  # Tendermint compatibility
      - Dilithium3 (ML-DSA-65)  # Post-quantum (NIST FIPS 204)
      - Dilithium5 (ML-DSA-87)  # High-security post-quantum

    key_encapsulation:
      - Kyber768 (ML-KEM-768)   # Post-quantum KEM (NIST FIPS 203)
      - X25519                   # Classical ECDH

    hashing:
      - SHA-256
      - SHA-3-256
      - BLAKE3

    symmetric:
      - AES-256-GCM
      - ChaCha20-Poly1305

  key_sizes:
    rsa_minimum: 4096           # If RSA is used
    ecdsa_curve: secp256k1
    dilithium_level: 3          # NIST Level 3 minimum
```

### Physical Security

```yaml
physical_security:
  # FIPS 140-3 Level 3 requirements
  tamper_protection:
    - tamper_evident_seals: required
    - tamper_responsive_circuitry: required
    - zeroization_on_tamper: required

  access_control:
    - multi_person_integrity: required      # M-of-N access
    - role_separation: required             # Admin vs Operator
    - audit_logging: required               # All access logged

  environmental:
    - temperature_monitoring: required
    - intrusion_detection: required
    - secure_facility: required             # Physical access control
```

### Network Security

```yaml
network_security:
  # HSM network configuration
  connectivity:
    - dedicated_network_segment: required
    - tls_1_3_minimum: required
    - mutual_authentication: required
    - ip_allowlisting: required

  high_availability:
    - hsm_cluster: recommended              # For production
    - geographic_redundancy: recommended    # Disaster recovery
    - automatic_failover: required          # Zero downtime
```

---

## Key Types and Hierarchy

### Key Hierarchy Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        HSM ROOT OF TRUST                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐ │
│  │   Master Key    │    │   Master Key    │    │   Master Key    │ │
│  │   (HSM Internal)│    │   (HSM Internal)│    │   (HSM Internal)│ │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘ │
│           │                      │                      │          │
│  ┌────────▼────────┐    ┌────────▼────────┐    ┌────────▼────────┐ │
│  │ Consensus Keys  │    │ Verification    │    │  Bridge Keys   │ │
│  │                 │    │     Keys        │    │                │ │
│  │ • ECDSA         │    │ • Dilithium3    │    │ • Ethereum     │ │
│  │ • Ed25519       │    │ • Attestation   │    │ • Cosmos IBC   │ │
│  │ • Dilithium3    │    │ • ZK Signing    │    │ • Relayer      │ │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘ │
│           │                      │                      │          │
│  ┌────────▼──────────────────────▼──────────────────────▼────────┐ │
│  │                    DERIVED SESSION KEYS                        │ │
│  │  (Short-lived, rotated per epoch or per-transaction)          │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Specifications

```yaml
key_specifications:
  # Consensus signing key (primary validator identity)
  consensus_key:
    algorithm: Ed25519
    purpose: "Tendermint consensus voting"
    rotation_policy: "Manual, with governance approval"
    backup: "M-of-N threshold scheme"
    hsm_slot: 1

  # Hybrid post-quantum key
  hybrid_key:
    algorithms:
      classical: ECDSA-secp256k1
      quantum: Dilithium3
    purpose: "Hybrid signatures for future-proofing"
    rotation_policy: "Annual or on quantum threat level change"
    hsm_slot: 2

  # TEE attestation signing key
  attestation_key:
    algorithm: ECDSA-P256
    purpose: "Sign TEE attestation reports"
    rotation_policy: "On enclave upgrade"
    hsm_slot: 3

  # Bridge relayer key
  bridge_key:
    algorithm: ECDSA-secp256k1
    purpose: "Sign cross-chain bridge transactions"
    rotation_policy: "Quarterly"
    hsm_slot: 4

  # ZK proof signing key
  zk_signing_key:
    algorithm: Dilithium3
    purpose: "Sign zkML verification results"
    rotation_policy: "On circuit upgrade"
    hsm_slot: 5
```

---

## Integration Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         AETHELRED VALIDATOR NODE                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐ │
│  │   CometBFT       │     │   PoUW Module    │     │   Bridge Module  │ │
│  │   Consensus      │     │   (Go)           │     │   (Rust)         │ │
│  └────────┬─────────┘     └────────┬─────────┘     └────────┬─────────┘ │
│           │                        │                        │           │
│           └────────────────────────┼────────────────────────┘           │
│                                    │                                     │
│                          ┌─────────▼─────────┐                          │
│                          │   HSM Signer      │                          │
│                          │   Interface       │                          │
│                          │   (PKCS#11)       │                          │
│                          └─────────┬─────────┘                          │
│                                    │                                     │
└────────────────────────────────────┼─────────────────────────────────────┘
                                     │
                            ┌────────▼────────┐
                            │   PKCS#11       │
                            │   Driver        │
                            └────────┬────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
           ┌────────▼────────┐ ┌────▼────┐ ┌────────▼────────┐
           │   Thales Luna   │ │ AWS     │ │   YubiHSM 2    │
           │   Network HSM   │ │ CloudHSM│ │                │
           └─────────────────┘ └─────────┘ └─────────────────┘
```

### PKCS#11 Interface

```go
// HSM signer interface for Aethelred
type HSMSigner interface {
    // Initialize connects to the HSM
    Initialize(config HSMConfig) error

    // GetPublicKey retrieves a public key from the HSM
    GetPublicKey(keyID string) (crypto.PublicKey, error)

    // Sign performs a signing operation within the HSM
    Sign(keyID string, digest []byte, algorithm SignatureAlgorithm) ([]byte, error)

    // SignHybrid performs hybrid ECDSA+Dilithium signing
    SignHybrid(ecdsaKeyID, dilithiumKeyID string, message []byte) (*HybridSignature, error)

    // GenerateKey creates a new key pair in the HSM
    GenerateKey(keyType KeyType, label string) (keyID string, err error)

    // WrapKey exports a key wrapped with another key
    WrapKey(keyID, wrappingKeyID string) ([]byte, error)

    // Close releases HSM resources
    Close() error
}

// HSM configuration
type HSMConfig struct {
    // PKCS#11 library path
    LibraryPath string `json:"library_path"`

    // HSM slot number
    Slot uint `json:"slot"`

    // PIN or password (should be injected securely)
    PIN string `json:"-"`

    // Connection pool size
    PoolSize int `json:"pool_size"`

    // Request timeout
    Timeout time.Duration `json:"timeout"`

    // Retry configuration
    MaxRetries int `json:"max_retries"`
    RetryBackoff time.Duration `json:"retry_backoff"`
}
```

---

## Configuration Guide

### Thales Luna Network HSM

```yaml
# config/hsm/luna.yaml
hsm:
  provider: thales_luna
  library_path: /usr/safenet/lunaclient/lib/libCryptoki2_64.so

  connection:
    slot: 0
    token_label: "AETHELRED_PROD"

  authentication:
    # Use environment variable for PIN
    pin_env: "LUNA_HSM_PIN"

    # Optional: Use PED for high-security deployments
    ped_enabled: false

  keys:
    consensus:
      label: "aethelred_consensus_v1"
      type: ed25519

    hybrid_ecdsa:
      label: "aethelred_hybrid_ecdsa_v1"
      type: ecdsa_secp256k1

    hybrid_dilithium:
      label: "aethelred_hybrid_dilithium_v1"
      type: dilithium3

    bridge:
      label: "aethelred_bridge_v1"
      type: ecdsa_secp256k1

  high_availability:
    enabled: true
    secondary_slot: 1
    failover_timeout: 5s
```

### AWS CloudHSM

```yaml
# config/hsm/aws_cloudhsm.yaml
hsm:
  provider: aws_cloudhsm

  cluster:
    cluster_id: "cluster-xxx"
    region: "us-east-1"

  connection:
    library_path: /opt/cloudhsm/lib/libcloudhsm_pkcs11.so

  authentication:
    # Crypto User credentials
    cu_username_env: "CLOUDHSM_CU_USERNAME"
    cu_password_env: "CLOUDHSM_CU_PASSWORD"

  keys:
    consensus:
      label: "aethelred-consensus-prod"
      key_spec: ECC_SECG_P256K1

    dilithium:
      # Note: Dilithium may require custom firmware
      label: "aethelred-dilithium-prod"
      key_spec: CUSTOM_DILITHIUM3
```

### YubiHSM 2 (Cost-Effective Option)

```yaml
# config/hsm/yubihsm.yaml
hsm:
  provider: yubihsm

  connection:
    # USB or network connector
    connector: "http://127.0.0.1:12345"

  authentication:
    auth_key_id: 1
    password_env: "YUBIHSM_PASSWORD"

  keys:
    consensus:
      id: 0x0001
      label: "aethelred_consensus"
      algorithm: ed25519

    ecdsa:
      id: 0x0002
      label: "aethelred_ecdsa"
      algorithm: secp256k1

  # YubiHSM 2 supports limited concurrent operations
  connection_pool:
    size: 4
    timeout: 10s
```

---

## Operational Procedures

### Key Ceremony Procedure

```markdown
## Key Generation Ceremony

### Prerequisites
- [ ] At least 3 Key Custodians present
- [ ] Secure, audited facility (no cameras, phones)
- [ ] Independent witness (auditor)
- [ ] Hardware: HSM, air-gapped laptop, secure USB drives

### Procedure

1. **Facility Preparation** (15 minutes)
   - Sweep room for electronic devices
   - Witness confirms secure environment
   - Set up air-gapped ceremony laptop

2. **HSM Initialization** (30 minutes)
   - Connect HSM to air-gapped laptop
   - Initialize HSM with factory reset
   - Create M-of-N admin quorum (recommended: 3-of-5)

3. **Key Generation** (45 minutes)
   - Generate consensus key (Ed25519)
   - Generate hybrid key pair (ECDSA + Dilithium3)
   - Generate bridge key (ECDSA)
   - Record public keys and key IDs

4. **Backup Creation** (30 minutes)
   - Create wrapped key backups
   - Split backup across M custodians
   - Store in geographically separate secure locations

5. **Verification** (15 minutes)
   - Verify all keys are accessible
   - Test signing operations
   - Document key fingerprints

6. **Ceremony Closure** (15 minutes)
   - Witness signs ceremony log
   - All custodians sign acknowledgment
   - Secure disposal of any temporary materials
```

### Key Rotation Procedure

```bash
#!/bin/bash
# Key rotation script for Aethelred HSM keys

set -euo pipefail

# Configuration
HSM_SLOT=0
NEW_KEY_LABEL="aethelred_consensus_v$(date +%Y%m%d)"
OLD_KEY_LABEL="$1"

echo "=== Aethelred HSM Key Rotation ==="
echo "Rotating key: $OLD_KEY_LABEL -> $NEW_KEY_LABEL"

# Step 1: Generate new key
echo "[1/5] Generating new key..."
pkcs11-tool --module $PKCS11_LIB --slot $HSM_SLOT \
    --login --pin env:HSM_PIN \
    --keypairgen --key-type EC:secp256k1 \
    --label "$NEW_KEY_LABEL"

# Step 2: Export new public key
echo "[2/5] Exporting new public key..."
NEW_PUBKEY=$(pkcs11-tool --module $PKCS11_LIB --slot $HSM_SLOT \
    --login --pin env:HSM_PIN \
    --read-object --type pubkey --label "$NEW_KEY_LABEL" | xxd -p)

# Step 3: Submit governance proposal for key rotation
echo "[3/5] Submitting governance proposal..."
aethelred tx validator rotate-key \
    --old-key-label "$OLD_KEY_LABEL" \
    --new-pubkey "$NEW_PUBKEY" \
    --from validator \
    --chain-id aethelred-mainnet-1

# Step 4: Wait for governance approval (manual step)
echo "[4/5] Waiting for governance approval..."
echo "Please approve the key rotation proposal via governance."
read -p "Press Enter after governance approval..."

# Step 5: Update validator configuration
echo "[5/5] Updating configuration..."
sed -i "s/$OLD_KEY_LABEL/$NEW_KEY_LABEL/g" /etc/aethelred/config/hsm.yaml

echo "=== Key rotation complete ==="
echo "New key label: $NEW_KEY_LABEL"
echo "Please restart the validator node."
```

---

## Compliance and Auditing

### Audit Log Requirements

```yaml
audit_requirements:
  # All HSM operations must be logged
  logging:
    - key_generation
    - key_destruction
    - signing_operations
    - authentication_attempts
    - configuration_changes
    - backup_operations

  # Log format
  log_format:
    timestamp: ISO8601
    operation: string
    key_id: string
    user: string
    result: success|failure
    details: object

  # Retention
  retention_period: 7_years
  immutable_storage: required

  # Real-time monitoring
  alerting:
    - failed_authentication: immediate
    - unusual_signing_volume: within_1_minute
    - key_destruction: immediate
    - configuration_change: immediate
```

### Compliance Frameworks

| Framework | HSM Requirements | Aethelred Support |
|-----------|------------------|-------------------|
| SOC 2 Type II | FIPS 140-2 Level 2+ | ✅ Supported |
| PCI DSS | FIPS 140-2 Level 3 | ✅ Supported |
| HIPAA | Encryption key management | ✅ Supported |
| GDPR | Data protection measures | ✅ Supported |
| MAS TRM | Key management controls | ✅ Supported |
| NIST 800-53 | Cryptographic protection | ✅ Supported |

---

## Disaster Recovery

### Recovery Procedures

```yaml
disaster_recovery:
  # HSM failure recovery
  hsm_failure:
    detection_time: "<5 minutes"
    failover_time: "<30 seconds"  # With HA cluster
    manual_recovery_time: "<4 hours"

    steps:
      1: "Detect HSM failure via monitoring"
      2: "Automatic failover to secondary HSM (if HA)"
      3: "Alert on-call team"
      4: "Assess failure severity"
      5: "Restore from backup if needed"
      6: "Verify key integrity"
      7: "Resume operations"

  # Complete key loss recovery
  key_loss:
    requires: "M-of-N custodian quorum"
    recovery_time: "<24 hours"

    steps:
      1: "Convene key custodians"
      2: "Retrieve backup shards"
      3: "Initialize new HSM"
      4: "Restore keys from shards"
      5: "Verify key fingerprints"
      6: "Submit key recovery governance proposal"
      7: "Resume operations after approval"

  # Geographic disaster
  geographic_disaster:
    requires: "Secondary site HSM"
    recovery_time: "<1 hour"

    steps:
      1: "Activate secondary site"
      2: "Verify HSM replication"
      3: "Update DNS/routing"
      4: "Resume operations"
```

### Backup Strategy

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        HSM BACKUP ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│     PRIMARY SITE                         SECONDARY SITE                  │
│   ┌─────────────┐                      ┌─────────────┐                  │
│   │   HSM       │ ───── Real-time ────▶│   HSM       │                  │
│   │   Primary   │      Replication      │  Secondary  │                  │
│   └──────┬──────┘                      └──────┬──────┘                  │
│          │                                     │                         │
│          │           OFFLINE BACKUPS           │                         │
│          │                                     │                         │
│   ┌──────▼──────┐                      ┌──────▼──────┐                  │
│   │  Wrapped    │                      │  Wrapped    │                  │
│   │  Key Backup │                      │  Key Backup │                  │
│   └──────┬──────┘                      └──────┬──────┘                  │
│          │                                     │                         │
│          └──────────────┬──────────────────────┘                         │
│                         │                                                │
│                         ▼                                                │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                    M-of-N CUSTODIAN SHARDS                       │   │
│   │                                                                  │   │
│   │   ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐                   │   │
│   │   │Shard│  │Shard│  │Shard│  │Shard│  │Shard│                   │   │
│   │   │  1  │  │  2  │  │  3  │  │  4  │  │  5  │                   │   │
│   │   └──┬──┘  └──┬──┘  └──┬──┘  └──┬──┘  └──┬──┘                   │   │
│   │      │        │        │        │        │                       │   │
│   │   Bank    Custodian   Escrow  Custodian  Secure                 │   │
│   │  Vault A    Home      Agent     Home   Vault B                  │   │
│   │  (NYC)    (London)   (Geneva)  (Tokyo) (Singapore)              │   │
│   │                                                                  │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Contact and Support

### HSM Integration Support

- **Technical Support**: hsm-support@aethelred.org
- **Security Incidents**: security@aethelred.org
- **Documentation**: https://docs.aethelred.org/security/hsm

### Vendor Support Contacts

| Vendor | Support Portal | SLA |
|--------|----------------|-----|
| Thales | supportportal.thalesgroup.com | 24/7 Premium |
| AWS CloudHSM | aws.amazon.com/cloudhsm | Enterprise Support |
| Azure | azure.microsoft.com/support | Premier Support |
| Yubico | support.yubico.com | Business Support |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-01-15 | Initial release |

---

*This document is part of the Aethelred Enterprise Security Documentation.*
