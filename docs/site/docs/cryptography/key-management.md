# Key Management

Lifecycle operations for Aethelred cryptographic keys: generation, rotation, backup, recovery, and multi-signature coordination.

## Key Generation

### Software Keys

```bash
# Generate a new Dilithium3 + ECDSA hybrid keypair (default)
aethelred key generate

# Generate with a specific algorithm
aethelred key generate --algorithm dilithium3
aethelred key generate --algorithm ecdsa
aethelred key generate --algorithm hybrid

# Import an existing key from file
aethelred key import ./my-key.pem

# List all keys in the active keyring
aethelred key list
```

All generated secret keys implement `ZeroizeOnDrop` -- memory is securely erased when the key object is dropped.

### HSM Keys

Keys generated inside an HSM are marked non-extractable. The private key never leaves the hardware boundary.

```bash
aethelred key generate --hsm \
  --module /opt/cloudhsm/lib/libcloudhsm_pkcs11.so \
  --label aethelred-validator-key
```

See [HSM Deployment](/cryptography/hsm-deployment) for full setup instructions.

## Key Types and Usage

| Key Type | Algorithm | Where Used |
|----------|-----------|------------|
| Validator Signing Key | Hybrid (ECDSA + Dilithium3) | Block signing, vote extensions |
| Account Key | ECDSA secp256k1 | Transaction signing, wallet operations |
| Seal Key | Dilithium3 | Digital seal creation and verification |
| KEM Key | Kyber768 | Encrypted key exchange between nodes |

## Key Rotation

Rotate keys periodically to limit the impact of a potential compromise.

### Validator Key Rotation

```bash
# 1. Generate the new key
aethelred key generate --label validator-key-2026-q2

# 2. Register the new key on-chain (requires governance proposal for MainNet)
aethelred validator update --signing-key validator-key-2026-q2

# 3. Wait for the key change to take effect (next epoch boundary)
aethelred validator status

# 4. Archive the old key (do not delete until fully rotated)
aethelred key export --format pem validator-key-2026-q1 > archived-key.pem
```

### Recommended Rotation Schedule

| Key Type | Rotation Frequency | Notes |
|----------|:------------------:|-------|
| Validator signing | Quarterly | Coordinate with epoch boundaries |
| Account keys | Annually | Update on-chain account info |
| KEM keys | Monthly | Automated via key agreement protocol |
| Seal keys | Semi-annually | Announce new key in seal metadata |

## Backup and Recovery

### Software Key Backup

```bash
# Export public key (safe to share)
aethelred key export --format pem my-key > my-key-pub.pem

# Export encrypted private key (guard this file carefully)
aethelred key export --format pem --secret my-key > my-key-secret.pem.enc
```

Store encrypted backups in at least two geographically separated locations. Use a strong passphrase -- the export process uses AES-256-GCM with Argon2id key derivation.

### HSM Key Backup

HSM keys cannot be exported. Use the vendor's cloning or backup mechanism:

| HSM | Backup Method |
|-----|---------------|
| AWS CloudHSM | Cluster-level backup to S3 (encrypted) |
| Thales Luna | Luna Backup HSM or Luna Cloud HSM backup |
| YubiHSM 2 | Wrap key under a backup key to another YubiHSM |

### Mnemonic Recovery

Account keys support BIP-39 mnemonic recovery:

```bash
# Create account with mnemonic backup
aethelred account create --name my-account
# The CLI displays a 24-word mnemonic -- record it offline

# Recover from mnemonic
aethelred account import --name my-account
# Prompts for the 24-word phrase
```

## Multi-Signature Keys

Aethelred supports m-of-n multi-sig for high-value operations such as treasury management and governance proposals.

```bash
# Create a 2-of-3 multi-sig account
aethelred account create-multisig \
  --name treasury \
  --threshold 2 \
  --pubkeys key1.pub,key2.pub,key3.pub

# Sign a transaction (each signer runs this independently)
aethelred tx sign --multisig treasury --from signer1 tx.json > sig1.json
aethelred tx sign --multisig treasury --from signer2 tx.json > sig2.json

# Combine signatures and broadcast
aethelred tx multisign tx.json treasury sig1.json sig2.json | aethelred tx broadcast
```

## Key Ceremony Checklist

For production MainNet key ceremonies:

1. **Prepare** -- air-gapped machine, two authorized operators, tamper-evident bags.
2. **Generate** -- create key inside HSM with `Extractable = false`.
3. **Record** -- export public key, compute fingerprint (`SHA3-256` of public key bytes).
4. **Register** -- submit on-chain transaction to associate the public key with the validator.
5. **Backup** -- clone HSM or create vendor-specific backup; store in secure vault.
6. **Attest** -- both operators sign a written log with serial numbers, timestamps, and fingerprints.
7. **Verify** -- query the chain to confirm the public key is registered and active.

## Revoking a Compromised Key

```bash
# Immediately rotate the validator signing key
aethelred validator update --signing-key new-emergency-key --emergency

# Notify the network via governance alert
aethelred tx submit-proposal key-revocation \
  --old-key <COMPROMISED_KEY_FINGERPRINT> \
  --reason "Key compromise detected"
```

## Further Reading

- [Cryptography Overview](/cryptography/overview) - Algorithm stack and hybrid design
- [Security Parameters](/cryptography/security-parameters) - Key sizes and wire format
- [HSM Deployment](/cryptography/hsm-deployment) - Hardware Security Module setup
