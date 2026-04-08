# Error Catalog

This document describes every structured error code returned by the Aethelred API. Error codes are shared across all official SDKs (Python, TypeScript, Go, Rust) and follow a consistent JSON envelope.

## Error Response Format

All errors are returned as JSON with the following structure:

```json
{
  "error": {
    "code": 3001,
    "category": "CRYPTO",
    "message": "Signature verification failed",
    "details": {},
    "request_id": "req_abc123",
    "timestamp": "2026-04-08T12:00:00Z"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `code` | integer | Yes | Numeric error code (see tables below) |
| `category` | string | Yes | Error category (`VALIDATION`, `CONSENSUS`, etc.) |
| `message` | string | Yes | Human-readable description |
| `details` | object | No | Additional structured information specific to the error |
| `request_id` | string | No | Unique identifier for the request, useful for support |
| `timestamp` | string | No | ISO 8601 timestamp of when the error occurred |

---

## Error Categories

| Category | Code Range | Description |
|----------|-----------|-------------|
| [VALIDATION](#validation-1000-1999) | 1000 -- 1999 | Input validation errors |
| [CONSENSUS](#consensus-2000-2999) | 2000 -- 2999 | Consensus and job lifecycle errors |
| [CRYPTO](#crypto-3000-3999) | 3000 -- 3999 | Cryptographic operation errors |
| [TEE](#tee-4000-4999) | 4000 -- 4999 | Trusted Execution Environment errors |
| [NETWORK](#network-5000-5999) | 5000 -- 5999 | Network and RPC errors |
| [STORAGE](#storage-6000-6999) | 6000 -- 6999 | Storage and persistence errors |
| [ZKML](#zkml-7000-7999) | 7000 -- 7999 | Zero-Knowledge ML proof errors |
| [BRIDGE](#bridge-8000-8999) | 8000 -- 8999 | Cross-chain bridge errors |
| [INTERNAL](#internal-9000-9999) | 9000 -- 9999 | Internal system errors |

---

## VALIDATION (1000-1999)

Input validation errors are returned when a request is malformed or contains invalid data. These are never retryable; the client must fix the request before resubmitting.

| Code | Name | HTTP | Message | Retryable | Recovery Action |
|------|------|------|---------|-----------|-----------------|
| 1001 | `VALIDATION_INVALID_ADDRESS` | 400 | Invalid account address format | No | Verify the address uses bech32 encoding with the `aethel` prefix |
| 1002 | `VALIDATION_INVALID_HASH` | 400 | Invalid hash format or length | No | Ensure the hash is a valid hex-encoded SHA-256 digest (64 characters) |
| 1003 | `VALIDATION_INVALID_PROOF_TYPE` | 400 | Invalid or unsupported proof type | No | Check `details.allowed` for supported proof types |
| 1004 | `VALIDATION_MISSING_REQUIRED_FIELD` | 400 | Required field is missing | No | Include the field named in `details.field` |
| 1005 | `VALIDATION_FIELD_TOO_LONG` | 400 | Field exceeds maximum length | No | Shorten the field value to at most `details.max_length` bytes |
| 1006 | `VALIDATION_INVALID_FEE` | 400 | Fee amount is invalid or below minimum | No | Set the fee to at least `details.minimum` |
| 1007 | `VALIDATION_INVALID_SIGNATURE` | 400 | Signature format is invalid | No | Re-sign the request using the composite signature scheme |
| 1008 | `VALIDATION_EXPIRED_REQUEST` | 400 | Request has expired | No | Resubmit with a fresh timestamp; requests expire after 60 seconds |

---

## CONSENSUS (2000-2999)

Errors related to compute job lifecycle, validator consensus, and seal management.

| Code | Name | HTTP | Message | Retryable | Recovery Action |
|------|------|------|---------|-----------|-----------------|
| 2001 | `CONSENSUS_JOB_NOT_FOUND` | 404 | Compute job not found | No | Verify the job ID; it may have been pruned after the retention window |
| 2002 | `CONSENSUS_JOB_ALREADY_COMPLETED` | 409 | Job has already been completed | No | Fetch the existing result instead of resubmitting |
| 2003 | `CONSENSUS_JOB_EXPIRED` | 410 | Job has expired before completion | No | Submit a new job; expired jobs cannot be resumed |
| 2004 | `CONSENSUS_INSUFFICIENT_VERIFICATIONS` | 425 | Insufficient validator verifications | Yes | Wait and retry; more validators may come online |
| 2005 | `CONSENSUS_VERIFICATION_MISMATCH` | 409 | Validator verification results do not match | No | Investigate the job inputs; conflicting results indicate non-determinism |
| 2006 | `CONSENSUS_INVALID_STATE_TRANSITION` | 409 | Invalid job state transition | No | Check `details.current_state` and only request valid transitions |
| 2007 | `CONSENSUS_NO_AVAILABLE_VALIDATORS` | 503 | No validators available for the requested proof type | Yes | Retry with exponential backoff; validators may be temporarily offline |
| 2008 | `CONSENSUS_SEAL_NOT_FOUND` | 404 | AI Seal not found | No | Verify the seal ID; it may not have been issued yet |
| 2009 | `CONSENSUS_SEAL_REVOKED` | 410 | AI Seal has been revoked | No | The seal is permanently invalid; a new job submission is required |

---

## CRYPTO (3000-3999)

Errors from cryptographic operations including signature verification, hashing, encryption, and post-quantum primitives.

| Code | Name | HTTP | Message | Retryable | Recovery Action |
|------|------|------|---------|-----------|-----------------|
| 3001 | `CRYPTO_SIGNATURE_VERIFICATION_FAILED` | 401 | Signature verification failed | No | Ensure the signing key matches the address in `X-Aethelred-Address` |
| 3002 | `CRYPTO_INVALID_PUBLIC_KEY` | 400 | Invalid public key format | No | Verify both ECDSA and Dilithium3 public keys are correctly encoded |
| 3003 | `CRYPTO_HASH_MISMATCH` | 400 | Hash verification failed | No | Recompute the hash; compare `details.expected` with `details.actual` |
| 3004 | `CRYPTO_ENCRYPTION_FAILED` | 500 | Encryption operation failed | No | This is a server-side error; contact support with the `request_id` |
| 3005 | `CRYPTO_DECRYPTION_FAILED` | 400 | Decryption operation failed | No | Verify the ciphertext and key are correct |
| 3006 | `CRYPTO_UNSUPPORTED_ALGORITHM` | 400 | Cryptographic algorithm not supported | No | Use one of the algorithms listed in `details.supported` |
| 3007 | `CRYPTO_KEY_DERIVATION_FAILED` | 500 | Key derivation operation failed | No | Server-side error; contact support with the `request_id` |
| 3008 | `CRYPTO_PQC_NOT_AVAILABLE` | 501 | Post-quantum cryptography not available | No | The node does not support PQC; connect to a PQC-enabled node |

---

## TEE (4000-4999)

Errors from Trusted Execution Environment operations including attestation, enclave verification, and remote attestation.

| Code | Name | HTTP | Message | Retryable | Recovery Action |
|------|------|------|---------|-----------|-----------------|
| 4001 | `TEE_ATTESTATION_FAILED` | 401 | TEE attestation verification failed | Yes | Retry; the attestation service may be temporarily unavailable |
| 4002 | `TEE_QUOTE_EXPIRED` | 401 | TEE quote has expired | Yes | Request a fresh attestation quote from the enclave |
| 4003 | `TEE_ENCLAVE_MISMATCH` | 401 | Enclave measurement does not match expected value | No | The enclave binary has changed; verify the deployment matches the expected MRENCLAVE |
| 4004 | `TEE_PLATFORM_NOT_SUPPORTED` | 400 | TEE platform not supported | No | Use one of the platforms listed in `details.supported` |
| 4005 | `TEE_REMOTE_ATTESTATION_TIMEOUT` | 504 | Remote attestation service timed out | Yes | Retry with backoff; the Intel/AMD attestation service may be slow |
| 4006 | `TEE_INVALID_REPORT_DATA` | 400 | TEE report data is invalid | No | Verify the report data matches the expected format for the platform |

---

## NETWORK (5000-5999)

Errors related to node connectivity, RPC communication, and rate limiting.

| Code | Name | HTTP | Message | Retryable | Recovery Action |
|------|------|------|---------|-----------|-----------------|
| 5001 | `NETWORK_CONNECTION_FAILED` | 503 | Failed to connect to node | Yes | Check network connectivity; try an alternate RPC endpoint |
| 5002 | `NETWORK_REQUEST_TIMEOUT` | 504 | Request timed out | Yes | Retry with backoff; consider increasing the client timeout |
| 5003 | `NETWORK_NODE_NOT_SYNCED` | 503 | Node is not synchronized | Yes | Wait for the node to finish syncing or connect to a different node |
| 5004 | `NETWORK_RATE_LIMITED` | 429 | Rate limit exceeded | Yes | Wait `details.retry_after_seconds` before retrying; see [rate limits](./AUTHENTICATION.md#rate-limits-by-authentication-level) |
| 5005 | `NETWORK_BROADCAST_FAILED` | 500 | Transaction broadcast failed | Yes | Retry; the transaction may have been rejected by a mempool policy |
| 5006 | `NETWORK_INVALID_RESPONSE` | 502 | Invalid response from node | Yes | The upstream node returned unexpected data; retry or try another node |

---

## STORAGE (6000-6999)

Errors related to data persistence, retrieval, and storage quotas.

| Code | Name | HTTP | Message | Retryable | Recovery Action |
|------|------|------|---------|-----------|-----------------|
| 6001 | `STORAGE_NOT_FOUND` | 404 | Resource not found in storage | No | Verify the resource identifier; the item may have been pruned |
| 6002 | `STORAGE_WRITE_FAILED` | 500 | Failed to write to storage | Yes | Retry with backoff; the storage backend may be temporarily degraded |
| 6003 | `STORAGE_READ_FAILED` | 500 | Failed to read from storage | Yes | Retry with backoff; if persistent, contact support |
| 6004 | `STORAGE_QUOTA_EXCEEDED` | 507 | Storage quota exceeded | No | Delete unused resources or request a quota increase |

---

## ZKML (7000-7999)

Errors related to Zero-Knowledge Machine Learning proof generation and verification.

| Code | Name | HTTP | Message | Retryable | Recovery Action |
|------|------|------|---------|-----------|-----------------|
| 7001 | `ZKML_PROOF_VERIFICATION_FAILED` | 400 | Zero-knowledge proof verification failed | No | Regenerate the proof; inputs or witness may have been corrupted |
| 7002 | `ZKML_INVALID_PROOF_FORMAT` | 400 | Invalid zero-knowledge proof format | No | Ensure the proof is serialized in the expected binary format |
| 7003 | `ZKML_VERIFYING_KEY_MISMATCH` | 400 | Verifying key does not match expected value | No | Use the verifying key that corresponds to the circuit used for proof generation |
| 7004 | `ZKML_PUBLIC_INPUT_MISMATCH` | 400 | Public inputs do not match expected values | No | Verify public inputs match the values committed during proof generation |
| 7005 | `ZKML_PROOF_SYSTEM_NOT_SUPPORTED` | 400 | Proof system not supported | No | Use one of the systems listed in `details.supported` (e.g., Groth16, Plonk) |
| 7006 | `ZKML_PROOF_TOO_LARGE` | 400 | Proof exceeds maximum size limit | No | Reduce proof complexity; maximum size is `details.max_size` bytes |

---

## BRIDGE (8000-8999)

Errors related to cross-chain bridge operations including deposits, withdrawals, and liquidity.

| Code | Name | HTTP | Message | Retryable | Recovery Action |
|------|------|------|---------|-----------|-----------------|
| 8001 | `BRIDGE_CHAIN_NOT_SUPPORTED` | 400 | Target chain not supported | No | Check the list of supported chains in the bridge configuration |
| 8002 | `BRIDGE_DEPOSIT_FAILED` | 500 | Bridge deposit failed | Yes | Retry; verify the deposit transaction was confirmed on the source chain |
| 8003 | `BRIDGE_WITHDRAWAL_PENDING` | 425 | Withdrawal is still in challenge period | Yes | Wait until `details.challenge_ends_at` before retrying the withdrawal claim |
| 8004 | `BRIDGE_INSUFFICIENT_LIQUIDITY` | 503 | Insufficient bridge liquidity | Yes | Retry later or reduce the transfer amount |
| 8005 | `BRIDGE_INVALID_PROOF` | 400 | Bridge proof verification failed | No | Regenerate the bridge proof with correct Merkle path data |

---

## INTERNAL (9000-9999)

Internal system errors that typically indicate transient server-side issues.

| Code | Name | HTTP | Message | Retryable | Recovery Action |
|------|------|------|---------|-----------|-----------------|
| 9001 | `INTERNAL_UNKNOWN_ERROR` | 500 | An unexpected error occurred | Yes | Retry with backoff; if persistent, report the `request_id` to support |
| 9002 | `INTERNAL_SERVICE_UNAVAILABLE` | 503 | Service temporarily unavailable | Yes | Retry with backoff; the service is likely restarting or under maintenance |
| 9003 | `INTERNAL_CONFIGURATION_ERROR` | 500 | Internal configuration error | No | Server misconfiguration; report the `request_id` to support |
| 9004 | `INTERNAL_CIRCUIT_BREAKER_OPEN` | 503 | Circuit breaker is open due to high error rate | Yes | Wait until `details.recovery_time` before retrying |

---

## SDK Error Handling

All official SDKs provide typed error classes that map to the error categories above. Retryable errors are automatically handled by the SDK retry middleware when configured.

### Retry Strategy

The default retry strategy uses exponential backoff with jitter:

| Parameter | Default Value |
|-----------|--------------|
| Max retries | 3 |
| Backoff type | Exponential |
| Initial delay | 100 ms |
| Max delay | 30,000 ms |
| Jitter | Enabled |

Only errors marked as `retryable: true` in the tables above are retried automatically.

### Python

```python
from aethelred import AethelredError, JobError, RateLimitError

try:
    result = await client.jobs.submit(...)
except RateLimitError as e:
    await asyncio.sleep(e.retry_after or 10)
    result = await client.jobs.submit(...)
except JobError as e:
    print(f"Job failed: {e.message} (code: {e.code}, job_id: {e.job_id})")
except AethelredError as e:
    print(f"Error: {e.message} (code: {e.code})")
```

The Python SDK exception hierarchy:

```
AethelredError
  +-- ValidationError
  +-- ConsensusError
  |     +-- JobError
  +-- CryptoError
  +-- TEEError
  +-- NetworkError
  |     +-- RateLimitError
  +-- StorageError
  +-- ZKMLError
  +-- BridgeError
  +-- InternalError
```

### TypeScript

```typescript
import { AethelredError, RateLimitError, JobError } from '@aethelred/sdk';

try {
  const result = await client.jobs.submit({...});
} catch (error) {
  if (error instanceof RateLimitError) {
    await sleep(error.retryAfter ?? 10000);
  } else if (error instanceof JobError) {
    console.error(`Job failed: ${error.message} (job: ${error.jobId})`);
  }
}
```

Type guards are also available:

```typescript
import { isRateLimitError, isJobError } from '@aethelred/sdk';

if (isRateLimitError(error)) {
  // error is narrowed to RateLimitError
}
```

### Rust

```rust
match client.jobs().submit(request).await {
    Err(AethelredError::RateLimit { retry_after }) => {
        tokio::time::sleep(Duration::from_secs(retry_after.unwrap_or(10))).await;
    }
    Err(AethelredError::Job { message, job_id }) => {
        eprintln!("Job failed: {} (id: {:?})", message, job_id);
    }
    Err(e) => eprintln!("Error: {}", e),
    Ok(response) => println!("Job: {}", response.job_id),
}
```

The Rust SDK uses `thiserror` for the error enum and implements `std::error::Error`.

### Go

```go
resp, err := c.Jobs.Submit(ctx, req)
if err != nil {
    if errors.Is(err, types.ErrRateLimited) {
        time.Sleep(10 * time.Second)
    }
    log.Fatalf("submit failed: %v", err)
}
```

Use `errors.As` to extract structured details:

```go
var aErr *types.AethelredError
if errors.As(err, &aErr) {
    fmt.Printf("code=%d category=%s message=%s\n",
        aErr.Code, aErr.Category, aErr.Message)
}
```

---

## HTTP Status Code Summary

| HTTP Status | Meaning | Typical Categories |
|-------------|---------|-------------------|
| 400 | Bad Request | VALIDATION, CRYPTO, TEE, ZKML, BRIDGE |
| 401 | Unauthorized | CRYPTO, TEE |
| 404 | Not Found | CONSENSUS, STORAGE |
| 409 | Conflict | CONSENSUS |
| 410 | Gone | CONSENSUS |
| 425 | Too Early | CONSENSUS, BRIDGE |
| 429 | Too Many Requests | NETWORK |
| 500 | Internal Server Error | CRYPTO, NETWORK, STORAGE, INTERNAL |
| 501 | Not Implemented | CRYPTO |
| 502 | Bad Gateway | NETWORK |
| 503 | Service Unavailable | CONSENSUS, NETWORK, BRIDGE, INTERNAL |
| 504 | Gateway Timeout | TEE, NETWORK |
| 507 | Insufficient Storage | STORAGE |

---

## Further Reading

- [Authentication Guide](./AUTHENTICATION.md) -- authentication methods and rate limits
- [REST API Reference](./rest.md) -- full endpoint documentation
- Source specification: [`integrations/api/errors/error_codes.json`](../../integrations/api/errors/error_codes.json)
