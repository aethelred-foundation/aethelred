# Aethelred HSM Deployment Guide

## Overview

Aethelred validator nodes can store signing keys inside PKCS#11-compliant Hardware Security Modules (HSMs). The private key **never leaves the HSM hardware boundary** — only signatures are returned to the application.

## Supported HSMs

| HSM | Connection | Use Case |
|-----|-----------|----------|
| **AWS CloudHSM** | PKCS#11 via `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so` | Cloud validators |
| **Thales Luna** | PKCS#11 via `/usr/safenet/lunaclient/lib/libCryptoki2_64.so` | Enterprise/on-prem |
| **YubiHSM 2** | PKCS#11 via `/usr/lib/libyubihsm_pkcs11.so` | Individual validators |
| **SoftHSM** | PKCS#11 via `/usr/lib/softhsm/libsofthsm2.so` | Development only |

## Quick Start

### 1. Generate Key in HSM

```bash
# Connect and generate a non-extractable signing key
aethelred hsm generate-key \
    --module /opt/cloudhsm/lib/libcloudhsm_pkcs11.so \
    --pin "crypto_user:$HSM_PASSWORD" \
    --label "validator-signing-key" \
    --algorithm ecdsa-secp256k1
```

### 2. Configure Validator

```toml
# ~/.aethelred/config.toml
[hsm]
enabled = true
module_path = "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so"
pin = "${AETHELRED_HSM_PIN}"  # Use env var
key_label = "validator-signing-key"
algorithm = "ecdsa-secp256k1"

# Reconnection settings
max_retries = 3
retry_delay_ms = 500
```

### 3. Start Validator

```bash
export AETHELRED_HSM_PIN="crypto_user:your_password"
aethelredd start --hsm
```

## Supported Signing Algorithms

| Algorithm | PKCS#11 Mechanism | Signature Size | Use Case |
|-----------|-------------------|---------------:|----------|
| ECDSA P-256 | `CKM_ECDSA` | 64B | General purpose |
| ECDSA P-384 | `CKM_ECDSA` | 96B | Higher security |
| ECDSA secp256k1 | `CKM_ECDSA` | 64B | **Aethelred default** |
| Ed25519 | `CKM_EDDSA` | 64B | Cosmos SDK |
| RSA 2048 | `CKM_RSA_PKCS` | 256B | Legacy |
| RSA 4096 | `CKM_RSA_PKCS` | 512B | Legacy high-security |

## Security Properties

- **Non-extractable keys**: Generated with `CKA_EXTRACTABLE = false`
- **Automatic zeroization**: Session secrets are cleared on disconnect
- **Auto-reconnect**: Transparent reconnection with retry on transient failures
- **Metrics**: Sign operation count and error count are tracked via `metrics()`

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ModuleLoadFailed` | PKCS#11 library not found | Verify `module_path` points to correct `.so` file |
| `InitializationFailed` | HSM not initialized | Run HSM vendor initialization (e.g., `cloudhsm_mgmt_util`) |
| `LoginFailed` | Wrong PIN format | CloudHSM: `crypto_user:password`, Luna: plain password |
| `KeyNotFound` | Key label mismatch | Run `pkcs11-tool --list-objects` to verify label |
| `SessionExpired` | HSM timeout | Auto-reconnect handles this; increase `max_retries` if needed |
