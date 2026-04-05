# Aethelred API Reference

Complete API reference for the Aethelred blockchain REST and gRPC endpoints.

## Base URLs

| Environment | REST API | gRPC | WebSocket |
|-------------|----------|------|-----------|
| Mainnet | `https://api.mainnet.aethelred.io` | `grpc.mainnet.aethelred.io:9090` | `wss://ws.mainnet.aethelred.io` |
| Testnet | `https://api.testnet.aethelred.io` | `grpc.testnet.aethelred.io:9090` | `wss://ws.testnet.aethelred.io` |
| Devnet | `https://api.devnet.aethelred.io` | `grpc.devnet.aethelred.io:9090` | `wss://ws.devnet.aethelred.io` |
| Local | `http://localhost:1317` | `localhost:9090` | `ws://localhost:26657/websocket` |

## Authentication

Most read endpoints don't require authentication. Write operations require a signed transaction.

```bash
# Optional API key for rate limit increase
curl -H "X-API-Key: your-api-key" https://api.mainnet.aethelred.io/v1/jobs
```

---

## Jobs API

### Submit Job

Create a new compute job.

```http
POST /v1/jobs
Content-Type: application/json

{
  "model_hash": "base64-encoded-32-bytes",
  "input_hash": "base64-encoded-32-bytes",
  "proof_type": "PROOF_TYPE_TEE",
  "priority": 5,
  "max_gas": 1000000,
  "timeout_blocks": 100,
  "callback_url": "https://your-webhook.com/callback",
  "metadata": {
    "application": "credit-scoring",
    "version": "1.0"
  }
}
```

**Response:**
```json
{
  "job_id": "job_abc123def456",
  "tx_hash": "0x...",
  "estimated_blocks": 5
}
```

### Get Job

```http
GET /v1/jobs/{job_id}
```

**Response:**
```json
{
  "id": "job_abc123def456",
  "creator": "aethel1...",
  "model_hash": "base64...",
  "input_hash": "base64...",
  "output_hash": "base64...",
  "status": "JOB_STATUS_COMPLETED",
  "proof_type": "PROOF_TYPE_TEE",
  "priority": 5,
  "max_gas": 1000000,
  "timeout_blocks": 100,
  "created_at": "2024-01-15T10:30:00Z",
  "completed_at": "2024-01-15T10:30:45Z",
  "validator_address": "aethelvaloper1...",
  "metadata": {}
}
```

### List Jobs

```http
GET /v1/jobs?status=pending&creator=aethel1...&limit=20&offset=0&sort=created_at:desc
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status: `pending`, `computing`, `completed`, `failed` |
| `creator` | string | Filter by creator address |
| `model_hash` | string | Filter by model hash |
| `limit` | integer | Max results (default: 20, max: 100) |
| `offset` | integer | Pagination offset |
| `sort` | string | Sort field and direction: `created_at:desc` |

**Response:**
```json
{
  "jobs": [...],
  "total": 150,
  "next_key": "base64..."
}
```

### Cancel Job

```http
DELETE /v1/jobs/{job_id}
```

**Response:**
```json
{
  "tx_hash": "0x...",
  "refunded_amount": "1000000uaethel"
}
```

### Get Job Result

```http
GET /v1/jobs/{job_id}/result
```

**Response:**
```json
{
  "job_id": "job_abc123",
  "output_hash": "base64...",
  "output_data": "base64...",
  "verified": true,
  "consensus_validators": 10,
  "total_voting_power": 1000000
}
```

---

## Seals API

### Create Seal

```http
POST /v1/seals
Content-Type: application/json

{
  "job_id": "job_abc123",
  "expires_in_blocks": 10000,
  "regulatory_info": {
    "jurisdiction": "UAE",
    "compliance_frameworks": ["SOC2", "GDPR"],
    "data_classification": "confidential",
    "retention_period": "7 years"
  },
  "metadata": {}
}
```

**Response:**
```json
{
  "seal_id": "seal_xyz789",
  "tx_hash": "0x..."
}
```

### Get Seal

```http
GET /v1/seals/{seal_id}
```

**Response:**
```json
{
  "id": "seal_xyz789",
  "job_id": "job_abc123",
  "model_hash": "base64...",
  "input_commitment": "base64...",
  "output_commitment": "base64...",
  "model_commitment": "base64...",
  "status": "SEAL_STATUS_ACTIVE",
  "requester": "aethel1...",
  "validators": [
    {
      "validator_address": "aethelvaloper1...",
      "signature": "base64...",
      "timestamp": "2024-01-15T10:30:45Z",
      "voting_power": 100000
    }
  ],
  "tee_attestation": {
    "platform": "TEE_PLATFORM_AWS_NITRO",
    "quote": "base64...",
    "enclave_hash": "base64...",
    "timestamp": "2024-01-15T10:30:45Z",
    "pcr_values": {}
  },
  "zkml_proof": {
    "proof_system": "PROOF_SYSTEM_EZKL",
    "proof": "base64...",
    "public_inputs": ["base64..."],
    "verifying_key_hash": "base64..."
  },
  "regulatory_info": {...},
  "created_at": "2024-01-15T10:30:45Z",
  "expires_at": "2024-02-15T10:30:45Z"
}
```

### List Seals

```http
GET /v1/seals?status=active&requester=aethel1...&limit=20
```

### Verify Seal

```http
POST /v1/seals/{seal_id}/verify
```

**Response:**
```json
{
  "valid": true,
  "seal": {...},
  "verification_details": {
    "signature_valid": true,
    "tee_attestation_valid": true,
    "zkml_proof_valid": true,
    "not_expired": true,
    "not_revoked": true,
    "consensus_threshold_met": true
  },
  "errors": []
}
```

### Revoke Seal

```http
POST /v1/seals/{seal_id}/revoke
Content-Type: application/json

{
  "reason": "Data privacy request"
}
```

---

## Models API

### Register Model

```http
POST /v1/models
Content-Type: application/json

{
  "model_hash": "base64...",
  "name": "Credit Scorer v1",
  "architecture": "XGBoost",
  "version": "1.0.0",
  "category": "UTILITY_CATEGORY_FINANCIAL",
  "input_schema": "{\"type\": \"object\", ...}",
  "output_schema": "{\"type\": \"object\", ...}",
  "storage_uri": "ipfs://Qm...",
  "metadata": {}
}
```

**Response:**
```json
{
  "model_hash": "base64...",
  "tx_hash": "0x..."
}
```

### Get Model

```http
GET /v1/models/{model_hash}
```

**Response:**
```json
{
  "model_hash": "base64...",
  "name": "Credit Scorer v1",
  "owner": "aethel1...",
  "architecture": "XGBoost",
  "version": "1.0.0",
  "category": "UTILITY_CATEGORY_FINANCIAL",
  "input_schema": "...",
  "output_schema": "...",
  "storage_uri": "ipfs://Qm...",
  "registered_at": "2024-01-15T10:30:00Z",
  "verified": true,
  "total_jobs": 1500
}
```

### List Models

```http
GET /v1/models?category=financial&verified=true&limit=20
```

---

## Validators API

### List Validators

```http
GET /v1/validators?limit=50&sort=voting_power:desc
```

**Response:**
```json
{
  "validators": [
    {
      "address": "aethelvaloper1...",
      "moniker": "Validator One",
      "voting_power": 500000,
      "commission": 0.05,
      "jobs_completed": 10000,
      "jobs_failed": 50,
      "average_latency_ms": 150,
      "uptime_percentage": 99.9,
      "reputation_score": 9.5,
      "total_rewards": "1000000000uaethel",
      "slashing_events": 0,
      "hardware_capabilities": {
        "tee_platforms": ["TEE_PLATFORM_AWS_NITRO", "TEE_PLATFORM_INTEL_SGX"],
        "zkml_supported": true,
        "max_model_size_mb": 1024,
        "gpu_memory_gb": 80,
        "cpu_cores": 64,
        "memory_gb": 256
      }
    }
  ],
  "total": 100
}
```

### Get Validator

```http
GET /v1/validators/{address}
```

### Get Validator Stats

```http
GET /v1/validators/{address}/stats
```

---

## Verification API

### Verify TEE Attestation

```http
POST /v1/verification/tee
Content-Type: application/json

{
  "platform": "TEE_PLATFORM_AWS_NITRO",
  "quote": "base64...",
  "enclave_hash": "base64...",
  "nonce": "base64..."
}
```

**Response:**
```json
{
  "valid": true,
  "attestation": {...},
  "verified_at": "2024-01-15T10:30:45Z"
}
```

### Verify zkML Proof

```http
POST /v1/verification/zkml
Content-Type: application/json

{
  "proof_system": "PROOF_SYSTEM_EZKL",
  "proof": "base64...",
  "public_inputs": ["base64..."],
  "verifying_key_hash": "base64..."
}
```

---

## Network API

### Get Network Info

```http
GET /v1/network/info
```

**Response:**
```json
{
  "node_info": {
    "default_node_id": "...",
    "listen_addr": "...",
    "network": "aethelred-testnet-1",
    "version": "1.0.0",
    "moniker": "node-1"
  },
  "sync_info": {
    "latest_block_hash": "...",
    "latest_block_height": 123456,
    "latest_block_time": "2024-01-15T10:30:45Z",
    "catching_up": false
  }
}
```

### Get Network Stats

```http
GET /v1/network/stats
```

**Response:**
```json
{
  "total_jobs": 150000,
  "completed_jobs": 145000,
  "failed_jobs": 1000,
  "total_useful_work_units": "1000000000",
  "jobs_by_category": {
    "financial": 50000,
    "medical": 30000,
    "general": 70000
  },
  "active_validators": 100,
  "average_job_latency_ms": 250
}
```

### Get Epoch Stats

```http
GET /v1/network/epoch/{epoch_number}
```

---

## WebSocket API

### Subscribe to Jobs

```javascript
const ws = new WebSocket('wss://ws.testnet.aethelred.io');

ws.send(JSON.stringify({
  type: 'subscribe',
  channel: 'jobs',
  filters: {
    status: ['pending', 'computing'],
    creator: 'aethel1...'
  }
}));

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Job update:', data);
};
```

### Subscribe to Seals

```javascript
ws.send(JSON.stringify({
  type: 'subscribe',
  channel: 'seals',
  filters: {
    status: ['active']
  }
}));
```

### Subscribe to Blocks

```javascript
ws.send(JSON.stringify({
  type: 'subscribe',
  channel: 'blocks'
}));
```

---

## Error Responses

All errors follow a consistent format:

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Job not found",
    "details": {
      "job_id": "job_invalid123"
    }
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_REQUEST` | 400 | Invalid request parameters |
| `UNAUTHORIZED` | 401 | Authentication required |
| `FORBIDDEN` | 403 | Permission denied |
| `NOT_FOUND` | 404 | Resource not found |
| `CONFLICT` | 409 | Resource already exists |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |
| `SERVICE_UNAVAILABLE` | 503 | Service temporarily unavailable |

---

## Rate Limits

| Tier | Requests/min | Requests/day |
|------|--------------|--------------|
| Anonymous | 30 | 1,000 |
| Authenticated | 300 | 50,000 |
| Enterprise | 3,000 | Unlimited |

Rate limit headers:
```
X-RateLimit-Limit: 300
X-RateLimit-Remaining: 295
X-RateLimit-Reset: 1705321845
```

---

## Pagination

List endpoints support cursor-based pagination:

```http
GET /v1/jobs?limit=20&cursor=eyJpZCI6Impv...
```

Response includes:
```json
{
  "jobs": [...],
  "next_cursor": "eyJpZCI6Impv...",
  "has_more": true
}
```

---

## Versioning

The API is versioned in the URL path (`/v1/`). Breaking changes require a new version.

Current version: **v1**

---

## SDKs

Official SDKs handle authentication, pagination, and error handling:

- [Python SDK (source)](sdk/python)
- [TypeScript SDK (source)](sdk/typescript)
- [Rust SDK (source)](sdk/rust)
- [Go SDK (source)](sdk/go)
- [Publishing status](docs/sdk/PUBLISHING.md)
