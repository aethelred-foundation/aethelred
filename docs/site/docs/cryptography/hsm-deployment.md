# HSM Deployment

Aethelred supports Hardware Security Modules (HSMs) via the PKCS#11 interface for validator block signing. Private keys **never leave the HSM hardware boundary**.

## Supported HSMs

| HSM | FIPS Level | Certification | Use Case |
|-----|:----------:|---------------|----------|
| AWS CloudHSM | FIPS 140-2 Level 3 | PCI-DSS, SOC2 | Cloud validators |
| Thales Luna | FIPS 140-2 Level 3 | Common Criteria EAL4+ | Enterprise / on-prem |
| YubiHSM 2 | FIPS 140-2 Level 3 | -- | Development, small validators |
| SoftHSM | None | -- | **Development only** |

## Prerequisites

Build the CLI (or node) with HSM support enabled:

```bash
cargo build --release --features hsm
```

## PKCS#11 Module Paths

| HSM | Default Module Path |
|-----|---------------------|
| AWS CloudHSM | `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so` |
| Thales Luna | `/usr/safenet/lunaclient/lib/libCryptoki2_64.so` |
| YubiHSM 2 | `/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so` |
| SoftHSM | `/usr/lib/softhsm/libsofthsm2.so` |

## YubiHSM 2 Setup

A cost-effective option for smaller validator deployments.

```bash
# 1. Install the YubiHSM SDK
sudo apt install yubihsm-shell yubihsm-pkcs11

# 2. Start the yubihsm-connector service
yubihsm-connector -d

# 3. Generate a signing key inside the HSM
aethelred key generate --hsm \
  --module /usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so \
  --label aethelred-validator-key

# 4. Verify the key was created
aethelred key list --hsm \
  --module /usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so
```

## AWS CloudHSM Setup

```bash
# 1. Install the CloudHSM client
sudo yum install -y aws-cloudhsm-client aws-cloudhsm-pkcs11

# 2. Configure the cluster IP
sudo /opt/cloudhsm/bin/configure -a <HSM_IP>

# 3. Start the client daemon
sudo systemctl start cloudhsm-client

# 4. Generate a key (pass credentials as user:password)
aethelred key generate --hsm \
  --module /opt/cloudhsm/lib/libcloudhsm_pkcs11.so \
  --pin "crypto_user:MySecurePassword" \
  --label aethelred-validator-key
```

## Azure Managed HSM

Azure Managed HSM is accessed through the PKCS#11 library provided by the Azure SDK:

```bash
# Install the Azure HSM PKCS#11 module
sudo apt install azure-managed-hsm-pkcs11

# Generate a key
aethelred key generate --hsm \
  --module /usr/lib/azure/libazure_managed_hsm_pkcs11.so \
  --pin "$AZURE_HSM_PIN" \
  --label aethelred-validator-key
```

## HSM Configuration in `config.toml`

```toml
[hsm]
enabled = true
module_path = "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so"
key_label = "aethelred-validator-key"
pin = "${AETHELRED_HSM_PIN}"  # Use env variable for secrets
algorithm = "ecdsa-p256"       # ecdsa-p256, ecdsa-p384, ecdsa-secp256k1, ed25519
session_timeout = 300          # seconds
auto_reconnect = true
max_reconnect_attempts = 3
```

::: warning
Never store the HSM PIN in plaintext config files. Use the `AETHELRED_HSM_PIN` environment variable or a secrets manager.
:::

## Supported Signing Algorithms

| Algorithm | Signature Size | Notes |
|-----------|:--------------:|-------|
| ECDSA P-256 | 64 bytes | **Default** for HSM signing |
| ECDSA P-384 | 96 bytes | Higher security curve |
| ECDSA secp256k1 | 64 bytes | Bitcoin/Ethereum compatible |
| Ed25519 | 64 bytes | Edwards curve |
| RSA 2048 | 256 bytes | Legacy support |
| RSA 4096 | 512 bytes | Legacy support |

## Key Provisioning Ceremony

For production MainNet validators, follow this ceremony:

1. **Two-person rule** -- at least two authorized operators must be present.
2. **Air-gapped initialization** -- initialize the HSM on an air-gapped machine.
3. **Generate key inside HSM** -- the key is created with `Extractable = false` and `Sensitive = true`.
4. **Record the public key** -- export and register the public key on-chain.
5. **Backup via HSM cloning** -- use the HSM vendor's secure backup mechanism (not key export).
6. **Document and audit** -- log the ceremony with witnesses, serial numbers, and timestamps.

## Validator HSM Failover

The `ValidatorHsmSigner` supports a primary + backup HSM configuration:

```rust
let primary = HsmSigner::connect(primary_module, pin, "aethelred-validator-key")?;
let backup  = HsmSigner::connect(backup_module,  pin, "aethelred-validator-key")?;

let signer = ValidatorHsmSigner::new(primary, Some(backup));

// Automatically fails over to backup if primary is unreachable
let signature = signer.sign_block(&block_hash)?;
```

Health checks are available via `signer.health_check()` which returns the status of both HSMs.

## Further Reading

- [Cryptography Overview](/cryptography/overview) - Algorithm stack and hybrid design
- [Security Parameters](/cryptography/security-parameters) - Key and signature sizes
- [Key Management](/cryptography/key-management) - Rotation, backup, and recovery
