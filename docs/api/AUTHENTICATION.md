# Authentication

## Overview

The Aethelred API uses a tiered authentication model:

- **Read endpoints** are public. No authentication is required to query job status, fetch seals, or read network state.
- **Write endpoints** (submitting jobs, revoking seals, etc.) require a cryptographic signature. Clients must include `X-Aethelred-Signature` and `X-Aethelred-Address` headers on every mutating request.
- **API key authentication** (`X-API-Key`) is available for read-heavy integrations that need higher rate limits without signing every call.

All endpoints are served over TLS. Plaintext HTTP connections are rejected.

---

## Authentication Methods

### API Key

The simplest authentication method. Pass an API key via the `X-API-Key` header on each request. API keys are suitable for:

- Read-only dashboard integrations
- Rate-limited polling services
- Development and prototyping

API keys do **not** authorize write operations on their own. To submit jobs or modify state you must also provide a signed request.

**Obtaining an API key:** Generate keys from the Aethelred Dashboard or via the CLI:

```bash
aethelred keys create --name "my-service" --scope read
```

### Signed Requests

Required for all write operations. Signed requests use Aethelred's dual-key composite signature scheme combining classical ECDSA (secp256k1) with post-quantum Dilithium3 lattice-based signatures.

When both `X-API-Key` and `X-Aethelred-Signature` are present, the signature is verified first and the API key is used only for rate-limit accounting.

---

## Dual-Key Architecture

Aethelred employs a **post-quantum hybrid signature** scheme. Every wallet holds two keypairs:

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Classical key | ECDSA on secp256k1 | Backwards-compatible with existing blockchain tooling |
| Post-quantum key | CRYSTALS-Dilithium3 (NIST FIPS 204) | Resistant to quantum attacks on elliptic-curve cryptography |

A valid Aethelred signature is a **composite** of both signatures. Validators verify both components independently; a request is accepted only when both pass. This design ensures:

1. **Backwards compatibility** -- tooling that understands secp256k1 can still inspect the classical portion of any signature.
2. **Quantum resistance** -- even if ECDSA is broken by a sufficiently powerful quantum computer, the Dilithium3 component protects the integrity of the signature.
3. **Defence in depth** -- compromising a single key does not allow forgery.

---

## Signing Process

The following steps produce a valid composite signature for a write request.

### Step 1: Canonical Serialization

Serialize the request body to **canonical JSON**: keys sorted lexicographically, no extraneous whitespace.

```
{"input_hash":"sha256:def...","model_hash":"sha256:abc..."}
```

### Step 2: Hash

Compute the SHA-256 digest of the canonical bytes.

```
digest = SHA-256(canonical_json_bytes)
```

### Step 3: Classical Signature

Sign the digest with your ECDSA (secp256k1) private key, producing a **64-byte** `r || s` signature (low-S normalized per BIP-62).

### Step 4: Post-Quantum Signature

Sign the same digest with your Dilithium3 private key, producing an approximately **3,309-byte** signature.

### Step 5: Composite Construction

Construct the composite signature using length-prefixed concatenation:

```
composite = len(ecdsa_sig) || ecdsa_sig || len(dilithium_sig) || dilithium_sig
```

Where `len()` is a 4-byte big-endian unsigned integer.

### Step 6: Encode and Attach Headers

Base64-encode (standard, padded) the composite bytes and set the following headers:

```
X-Aethelred-Signature: <base64_encoded_composite_signature>
X-Aethelred-Address: aethel1...
```

The address is a bech32-encoded identifier derived from the SHA-256 hash of both public keys concatenated, using the `aethel` human-readable prefix.

---

## SDK Examples

Each official SDK handles signing internally. You provide a wallet or API key; the SDK takes care of canonical serialization, hashing, and composite signature construction.

### Python

```python
from aethelred import AsyncAethelredClient, Config, DualKeyWallet

wallet = DualKeyWallet()  # generates fresh keypair
# Or from mnemonic:
# wallet = DualKeyWallet.from_mnemonic("word1 word2 ... word24")

config = Config.testnet()
async with AsyncAethelredClient(config.rpc_url, api_key="your_api_key") as client:
    response = await client.jobs.submit(
        model_hash=b"sha256:abc...",
        input_hash=b"sha256:def...",
    )
```

### TypeScript

```typescript
import { AethelredClient, Network } from '@aethelred/sdk';

const client = new AethelredClient({
  network: Network.TESTNET,
  apiKey: process.env.AETHELRED_API_KEY,
});

const result = await client.jobs.submit({
  modelHash: '0xabc123...',
  inputHash: '0xdef456...',
});
```

### Go

```go
c, _ := client.NewClient(client.Testnet,
    client.WithAPIKey(os.Getenv("AETHELRED_API_KEY")),
)
```

### Rust

```rust
let config = Config::testnet()
    .with_api_key(&std::env::var("AETHELRED_API_KEY")?);
let client = AethelredClient::with_config(config).await?;
```

### curl

```bash
curl -X POST https://rpc.testnet.aethelred.io/v1/compute/submit \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -H "X-Aethelred-Address: aethel1abc..." \
  -H "X-Aethelred-Signature: base64_composite_sig" \
  -d '{"model_hash":"sha256:abc...","input_hash":"sha256:def..."}'
```

---

## Key Management Best Practices

### Use Environment Variables

Never hard-code API keys or private keys in source code. Load them from environment variables at runtime.

```bash
export AETHELRED_API_KEY="aethkey_..."
export AETHELRED_MNEMONIC="word1 word2 ... word24"
```

### Encrypted Key Export

The SDK wallet objects support encrypted export and import for secure storage:

```python
# Export (encrypts with AES-256-GCM)
encrypted = wallet.export_keys(password="strong-passphrase")

# Import
wallet = DualKeyWallet.from_encrypted(encrypted, password="strong-passphrase")
```

### Key Rotation

Rotate API keys periodically. When rotating:

1. Generate a new key via the dashboard or CLI.
2. Deploy the new key to your services.
3. Verify the new key works in production.
4. Revoke the old key.

For wallet keys, transfer authority to a new address before decommissioning the old keypair.

### Additional Recommendations

- Store mnemonic phrases in a hardware security module (HSM) or secrets manager in production.
- Use separate API keys per service or environment (development, staging, production).
- Monitor key usage through the Aethelred Dashboard and set up alerts for anomalous patterns.
- Never transmit private keys or mnemonics over unencrypted channels.

---

## Rate Limits by Authentication Level

Rate limits are enforced per source IP for unauthenticated requests and per API key or address for authenticated requests.

| Auth Level | Read Limit | Write Limit | Heavy Query |
|-----------|-----------|------------|------------|
| None (public) | 100/10s | N/A | 10/60s |
| API Key | 500/10s | 20/10s | 50/60s |
| Signed | 500/10s | 20/10s | 50/60s |

**Heavy queries** include operations such as paginated history scans, bulk seal lookups, and proof-bundle downloads.

When a rate limit is exceeded the API returns HTTP `429 Too Many Requests` with a `Retry-After` header indicating the number of seconds to wait. All official SDKs handle this automatically with exponential backoff.

---

## Error Responses

Authentication failures return structured JSON errors. See the [Error Catalog](./ERROR_CATALOG.md) for the full list. Common authentication-related codes:

| Code | Name | HTTP | Description |
|------|------|------|-------------|
| 1007 | `VALIDATION_INVALID_SIGNATURE` | 400 | Signature format is malformed |
| 3001 | `CRYPTO_SIGNATURE_VERIFICATION_FAILED` | 401 | Signature does not verify against the claimed address |
| 3002 | `CRYPTO_INVALID_PUBLIC_KEY` | 400 | Public key cannot be decoded |
| 5004 | `NETWORK_RATE_LIMITED` | 429 | Rate limit exceeded |

---

## Further Reading

- [Error Catalog](./ERROR_CATALOG.md) -- complete list of error codes and recovery actions
- [REST API Reference](./rest.md) -- full endpoint documentation
- [Testnet Guide](https://docs.aethelred.io/guide/network) -- connecting to the testnet
