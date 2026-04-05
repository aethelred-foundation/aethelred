# REST API Reference

<p align="center">
  <strong>Aethelred Node RPC API</strong><br/>
  <em>Version 2.0.0 | OpenAPI 3.1.0 Compliant</em>
</p>

---

## Overview

The Aethelred REST API provides programmatic access to the blockchain, allowing you to submit compute jobs, query seals, manage accounts, and more.

### Base URLs

| Network | Base URL |
|---------|----------|
| **Mainnet** | `https://rpc.mainnet.aethelred.io` |
| **Testnet (Nebula)** | `https://rpc.testnet.aethelred.io` |
| **Devnet** | `https://rpc.devnet.aethelred.io` |
| **Local** | `http://localhost:26657` |

### Authentication

Public read endpoints require no authentication. Write endpoints require a signed request.

```http
POST /v1/compute/submit
Content-Type: application/json
X-Aethelred-Signature: <signature>
X-Aethelred-Address: <your-address>

{
  "model_id": "...",
  "encrypted_input": "..."
}
```

---

## Table of Contents

1. [Compute Jobs](#1-compute-jobs)
2. [Digital Seals](#2-digital-seals)
3. [Accounts](#3-accounts)
4. [Validators](#4-validators)
5. [Blocks & Transactions](#5-blocks--transactions)
6. [Models](#6-models)
7. [Governance](#7-governance)
8. [Utilities](#8-utilities)

---

## 1. Compute Jobs

### Submit Compute Job

Submit an AI inference job to the network.

```http
POST /v1/compute/jobs
```

**Request Body:**

```json
{
  "model_id": "credit-score-v3",
  "encrypted_input": "base64-encoded-encrypted-data",
  "hardware_requirement": "NVIDIA_H100_CC",
  "jurisdiction": "UAE",
  "compliance": ["UAE_DPL", "GDPR"],
  "max_fee": "1000000000000000000",
  "priority_fee": "100000000000000000",
  "zk_proof_required": true,
  "deadline": 1707400000
}
```

**Response:**

```json
{
  "job_id": "job-0x1234567890abcdef",
  "status": "SCHEDULED",
  "assigned_validator": "aethelredval1abc...",
  "estimated_completion": 1707399000,
  "estimated_cost": {
    "amount": "500000000000000000",
    "denom": "aethel"
  },
  "tx_hash": "0xabcdef1234567890..."
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| `201` | Job successfully submitted |
| `400` | Invalid request (missing fields, invalid model) |
| `402` | Insufficient balance for fee |
| `503` | No validators available for requirements |

---

### Get Job Status

Retrieve the current status of a compute job.

```http
GET /v1/compute/jobs/{job_id}
```

**Response:**

```json
{
  "job_id": "job-0x1234567890abcdef",
  "status": "COMPLETED",
  "model_id": "credit-score-v3",
  "hardware_used": "NVIDIA_H100_CC",
  "validator": "aethelredval1abc...",
  "jurisdiction": "UAE",
  "submitted_at": "2026-02-08T12:00:00Z",
  "started_at": "2026-02-08T12:00:01Z",
  "completed_at": "2026-02-08T12:00:03Z",
  "execution_time_ms": 2150,
  "seal_id": "aethel-seal-0xabcd1234...",
  "encrypted_result": "base64-encoded-encrypted-result",
  "attestation": {
    "type": "INTEL_SGX_DCAP",
    "report": "base64-encoded-attestation",
    "verified": true
  },
  "zk_proof": {
    "available": true,
    "verified": true,
    "proof_size_bytes": 10240
  },
  "fee_paid": {
    "amount": "500000000000000000",
    "denom": "aethel"
  }
}
```

**Job Status Values:**

| Status | Description |
|--------|-------------|
| `PENDING` | Job submitted, awaiting routing |
| `SCHEDULED` | Assigned to validator, awaiting execution |
| `RUNNING` | Currently executing in TEE |
| `VERIFYING` | Execution complete, awaiting consensus |
| `COMPLETED` | Successfully completed with seal |
| `FAILED` | Execution failed (refund issued) |
| `TIMEOUT` | Exceeded deadline (refund issued) |

---

### List Jobs

List compute jobs for an account.

```http
GET /v1/compute/jobs?account={address}&status={status}&limit={limit}&offset={offset}
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `account` | string | No | Filter by submitter address |
| `status` | string | No | Filter by status |
| `model_id` | string | No | Filter by model |
| `limit` | integer | No | Max results (default 20, max 100) |
| `offset` | integer | No | Pagination offset |

**Response:**

```json
{
  "jobs": [
    {
      "job_id": "job-0x1234567890abcdef",
      "status": "COMPLETED",
      "model_id": "credit-score-v3",
      "submitted_at": "2026-02-08T12:00:00Z",
      "seal_id": "aethel-seal-0xabcd1234..."
    }
  ],
  "pagination": {
    "total": 150,
    "limit": 20,
    "offset": 0,
    "has_more": true
  }
}
```

---

### Estimate Job Cost

Get a cost estimate for a compute job before submitting.

```http
POST /v1/compute/estimate
```

**Request Body:**

```json
{
  "model_id": "credit-score-v3",
  "input_size_bytes": 1024,
  "hardware_requirement": "NVIDIA_H100_CC",
  "jurisdiction": "UAE",
  "zk_proof_required": true
}
```

**Response:**

```json
{
  "estimated_cost": {
    "base_fee": "200000000000000000",
    "hardware_premium": "100000000000000000",
    "jurisdiction_premium": "50000000000000000",
    "zk_proof_fee": "150000000000000000",
    "total": "500000000000000000",
    "denom": "aethel"
  },
  "estimated_time_seconds": 3,
  "available_validators": 12,
  "current_congestion": 0.45
}
```

---

## 2. Digital Seals

### Get Seal

Retrieve a digital seal by ID.

```http
GET /v1/seals/{seal_id}
```

**Response:**

```json
{
  "seal_id": "aethel-seal-0xabcd1234567890ef",
  "version": 1,
  "created_at": "2026-02-08T12:00:03Z",
  "block_height": 1234567,
  "tx_hash": "0xdef0123456789abc...",

  "computation": {
    "job_id": "job-0x1234567890abcdef",
    "model_id": "credit-score-v3",
    "model_hash": "0x1234567890abcdef...",
    "input_commitment": "0xabcdef1234567890...",
    "output_commitment": "0x567890abcdef1234...",
    "execution_time_ms": 2150
  },

  "validator": {
    "address": "aethelredval1abc...",
    "moniker": "UAE-Secure-Node-1",
    "hardware": "NVIDIA_H100_CC",
    "jurisdiction": "UAE"
  },

  "attestation": {
    "type": "INTEL_SGX_DCAP",
    "mr_enclave": "0x123456...",
    "mr_signer": "0xabcdef...",
    "tcb_level": "2024-01-15",
    "report": "base64-encoded-report",
    "signature": "base64-encoded-signature",
    "certificate_chain": ["cert1", "cert2", "cert3"]
  },

  "zk_proof": {
    "type": "HALO2",
    "proof": "base64-encoded-proof",
    "public_inputs": ["0x123...", "0x456...", "0x789..."],
    "verified": true
  },

  "compliance": {
    "regulations": ["UAE_DPL", "GDPR"],
    "jurisdiction": "UAE",
    "data_residency_verified": true
  },

  "signatures": {
    "validator_signature": "base64-signature",
    "hybrid_signature": {
      "ecdsa": "base64-ecdsa-sig",
      "dilithium": "base64-pq-sig"
    }
  }
}
```

---

### Verify Seal

Verify a seal's authenticity and attestation.

```http
POST /v1/seals/{seal_id}/verify
```

**Response:**

```json
{
  "seal_id": "aethel-seal-0xabcd1234567890ef",
  "verification_result": {
    "overall_valid": true,
    "checks": {
      "on_chain": {
        "valid": true,
        "block_height": 1234567,
        "confirmed": true
      },
      "attestation": {
        "valid": true,
        "hardware_verified": true,
        "tcb_not_revoked": true,
        "timestamp_valid": true
      },
      "signature": {
        "valid": true,
        "ecdsa_valid": true,
        "pq_valid": true
      },
      "zk_proof": {
        "valid": true,
        "public_inputs_match": true
      },
      "jurisdiction": {
        "valid": true,
        "expected": "UAE",
        "actual": "UAE"
      }
    }
  },
  "verified_at": "2026-02-08T12:00:10Z"
}
```

---

### List Seals

Query seals with filters.

```http
GET /v1/seals?model_id={model_id}&validator={address}&jurisdiction={jurisdiction}&from={timestamp}&to={timestamp}&limit={limit}
```

**Response:**

```json
{
  "seals": [
    {
      "seal_id": "aethel-seal-0xabcd1234...",
      "created_at": "2026-02-08T12:00:03Z",
      "model_id": "credit-score-v3",
      "validator": "aethelredval1abc...",
      "jurisdiction": "UAE"
    }
  ],
  "pagination": {
    "total": 5000,
    "limit": 20,
    "offset": 0,
    "has_more": true
  }
}
```

---

### Export Audit Report

Generate an audit report for a seal.

```http
GET /v1/seals/{seal_id}/audit?format={format}
```

**Query Parameters:**

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `format` | `json`, `pdf`, `html` | `json` | Export format |

**Response (JSON):**

```json
{
  "audit_report": {
    "seal_id": "aethel-seal-0xabcd1234...",
    "generated_at": "2026-02-08T12:00:15Z",
    "report_version": "2.0",

    "executive_summary": {
      "computation_verified": true,
      "attestation_valid": true,
      "compliance_met": true,
      "risk_level": "LOW"
    },

    "computation_details": {
      "model": "credit-score-v3",
      "model_hash": "0x1234...",
      "input_hash": "0xabcd...",
      "output_hash": "0xef12...",
      "execution_time": "2.15 seconds"
    },

    "security_details": {
      "hardware": "NVIDIA H100 Confidential Computing",
      "tee_type": "Intel SGX with DCAP",
      "attestation_chain": "Intel Root CA → Platform CA → Enclave",
      "tcb_status": "Up to date"
    },

    "compliance_details": {
      "regulations": ["UAE-DPL", "GDPR"],
      "data_residency": "UAE",
      "retention_policy": "7 years",
      "right_to_erasure": "Supported (output only)"
    },

    "cryptographic_evidence": {
      "signatures": ["ECDSA-P256", "Dilithium3"],
      "hashes": ["BLAKE3-256", "SHA3-256"],
      "proofs": ["HALO2 ZK-SNARK"]
    }
  }
}
```

**Response (PDF):**

Returns a PDF document suitable for regulatory submission.

---

## 3. Accounts

### Get Account

Retrieve account details and balances.

```http
GET /v1/accounts/{address}
```

**Response:**

```json
{
  "address": "aethelred1abc123def456...",
  "public_key": {
    "type": "HYBRID",
    "ecdsa": "base64-pubkey",
    "dilithium": "base64-pq-pubkey"
  },
  "sequence": 42,
  "account_number": 1234,

  "balances": {
    "available": {
      "amount": "1000000000000000000000",
      "denom": "aethel"
    },
    "staked": {
      "amount": "500000000000000000000",
      "denom": "aethel"
    },
    "unbonding": {
      "amount": "100000000000000000000",
      "denom": "aethel"
    },
    "locked": {
      "amount": "0",
      "denom": "aethel"
    }
  },

  "delegations": [
    {
      "validator": "aethelredval1xyz...",
      "amount": "250000000000000000000",
      "rewards_pending": "1000000000000000000"
    }
  ],

  "stats": {
    "total_jobs_submitted": 150,
    "total_fees_paid": "75000000000000000000",
    "total_seals_created": 148
  }
}
```

---

### Get Account Transactions

List transactions for an account.

```http
GET /v1/accounts/{address}/transactions?type={type}&limit={limit}&offset={offset}
```

**Response:**

```json
{
  "transactions": [
    {
      "tx_hash": "0xabc123...",
      "type": "MsgSubmitJob",
      "status": "SUCCESS",
      "height": 1234567,
      "timestamp": "2026-02-08T12:00:00Z",
      "fee": {
        "amount": "500000000000000000",
        "denom": "aethel"
      },
      "messages": [
        {
          "type": "/aethelred.compute.v1.MsgSubmitJob",
          "model_id": "credit-score-v3",
          "job_id": "job-0x123..."
        }
      ]
    }
  ],
  "pagination": {
    "total": 500,
    "limit": 20,
    "offset": 0
  }
}
```

---

## 4. Validators

### List Validators

Get all active validators.

```http
GET /v1/validators?status={status}&jurisdiction={jurisdiction}
```

**Response:**

```json
{
  "validators": [
    {
      "address": "aethelredval1abc...",
      "operator_address": "aethelred1xyz...",
      "consensus_pubkey": "base64-pubkey",
      "moniker": "UAE-Secure-Node-1",
      "description": "High-security validator in UAE",

      "status": "ACTIVE",
      "jailed": false,
      "tombstoned": false,

      "stake": {
        "self_stake": "100000000000000000000000",
        "delegated": "500000000000000000000000",
        "total": "600000000000000000000000",
        "voting_power_percent": 2.5
      },

      "hardware": {
        "tee_type": "NVIDIA_H100_CC",
        "attestation_status": "FRESH",
        "last_attestation": "2026-02-08T11:00:00Z"
      },

      "jurisdiction": {
        "primary": "UAE",
        "certifications": ["UAE_DPL", "GDPR", "PCI_DSS"]
      },

      "performance": {
        "uptime_30d": 99.95,
        "jobs_completed_30d": 15000,
        "avg_latency_ms": 45,
        "slashing_events": 0
      },

      "commission": {
        "rate": "0.10",
        "max_rate": "0.20",
        "max_change_rate": "0.01"
      }
    }
  ],
  "pagination": {
    "total": 100,
    "limit": 20,
    "offset": 0
  }
}
```

---

### Get Validator

Get details for a specific validator.

```http
GET /v1/validators/{address}
```

---

### Get Validator Attestation

Get the latest attestation for a validator.

```http
GET /v1/validators/{address}/attestation
```

**Response:**

```json
{
  "validator": "aethelredval1abc...",
  "attestation": {
    "type": "INTEL_SGX_DCAP",
    "generated_at": "2026-02-08T11:00:00Z",
    "expires_at": "2026-02-08T12:00:00Z",
    "status": "VALID",

    "hardware": {
      "vendor": "Intel",
      "model": "Xeon Platinum 8380",
      "sgx_version": "2.0"
    },

    "tcb": {
      "level": "2024-01-15",
      "status": "UP_TO_DATE",
      "advisory_ids": []
    },

    "enclave": {
      "mr_enclave": "0x1234567890abcdef...",
      "mr_signer": "0xabcdef1234567890...",
      "isv_prod_id": 1,
      "isv_svn": 5
    },

    "quote": "base64-encoded-quote",
    "certificate_chain": ["cert1", "cert2", "cert3"]
  }
}
```

---

## 5. Blocks & Transactions

### Get Block

```http
GET /v1/blocks/{height}
```

**Response:**

```json
{
  "height": 1234567,
  "hash": "0xabcdef123456...",
  "time": "2026-02-08T12:00:00Z",
  "proposer": "aethelredval1abc...",

  "header": {
    "chain_id": "aethelred-mainnet-1",
    "app_hash": "0x123456...",
    "consensus_hash": "0x789abc...",
    "validators_hash": "0xdef012..."
  },

  "txs_count": 150,
  "compute_jobs_count": 45,
  "seals_created": 42,

  "gas": {
    "used": 15000000,
    "limit": 40000000,
    "utilization": 0.375
  },

  "fees": {
    "total_collected": "5000000000000000000",
    "burned": "4500000000000000000",
    "to_proposer": "500000000000000000"
  }
}
```

---

### Get Transaction

```http
GET /v1/transactions/{hash}
```

**Response:**

```json
{
  "tx_hash": "0xabcdef123456...",
  "height": 1234567,
  "index": 42,
  "status": "SUCCESS",
  "timestamp": "2026-02-08T12:00:00Z",

  "from": "aethelred1xyz...",

  "messages": [
    {
      "type": "/aethelred.compute.v1.MsgSubmitJob",
      "model_id": "credit-score-v3",
      "job_id": "job-0x123...",
      "hardware_requirement": "NVIDIA_H100_CC",
      "jurisdiction": "UAE"
    }
  ],

  "fee": {
    "amount": "500000000000000000",
    "denom": "aethel",
    "gas_wanted": 200000,
    "gas_used": 185000
  },

  "signatures": [
    {
      "type": "HYBRID",
      "public_key": "base64-pubkey",
      "signature": "base64-signature"
    }
  ],

  "logs": [
    {
      "msg_index": 0,
      "events": [
        {
          "type": "submit_job",
          "attributes": [
            {"key": "job_id", "value": "job-0x123..."},
            {"key": "model_id", "value": "credit-score-v3"}
          ]
        }
      ]
    }
  ]
}
```

---

## 6. Models

### List Models

```http
GET /v1/models?category={category}&jurisdiction={jurisdiction}
```

**Response:**

```json
{
  "models": [
    {
      "model_id": "credit-score-v3",
      "name": "UAE Credit Scoring Model",
      "version": "3.0.0",
      "category": "FINANCE",

      "author": "aethelred1abc...",
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-02-01T00:00:00Z",

      "hash": "0x1234567890abcdef...",
      "size_bytes": 52428800,
      "architecture": "XGBoost",

      "hardware_requirements": ["NVIDIA_H100_CC", "INTEL_SGX"],
      "jurisdictions": ["UAE", "EU", "GLOBAL"],
      "compliance": ["UAE_DPL", "GDPR"],

      "stats": {
        "total_invocations": 150000,
        "avg_latency_ms": 45,
        "success_rate": 99.95
      },

      "pricing": {
        "base_fee": "100000000000000000",
        "per_unit_fee": "1000000000000000"
      }
    }
  ],
  "pagination": {
    "total": 50,
    "limit": 20,
    "offset": 0
  }
}
```

---

### Get Model

```http
GET /v1/models/{model_id}
```

---

### Register Model

```http
POST /v1/models
```

**Request Body:**

```json
{
  "name": "My Credit Scoring Model",
  "description": "GDPR-compliant credit scoring for EU market",
  "version": "1.0.0",
  "category": "FINANCE",
  "architecture": "LightGBM",

  "model_hash": "0x1234567890abcdef...",
  "weights_cid": "Qm...",

  "hardware_requirements": ["INTEL_SGX", "AMD_SEV"],
  "jurisdictions": ["EU", "UK"],
  "compliance": ["GDPR"],

  "input_schema": {
    "type": "object",
    "properties": {
      "income": {"type": "number"},
      "age": {"type": "integer"}
    }
  },

  "output_schema": {
    "type": "object",
    "properties": {
      "score": {"type": "number"},
      "risk_category": {"type": "string"}
    }
  },

  "registration_bond": "1000000000000000000000"
}
```

---

## 7. Governance

### List Proposals

```http
GET /v1/governance/proposals?status={status}
```

**Response:**

```json
{
  "proposals": [
    {
      "proposal_id": 42,
      "title": "Increase Base Fee Adjustment Speed",
      "description": "Proposal to increase the base fee adjustment...",
      "type": "PARAMETER_CHANGE",
      "status": "VOTING",
      "proposer": "aethelred1abc...",

      "submit_time": "2026-02-01T00:00:00Z",
      "deposit_end_time": "2026-02-05T00:00:00Z",
      "voting_start_time": "2026-02-05T00:00:00Z",
      "voting_end_time": "2026-02-12T00:00:00Z",

      "deposit": {
        "amount": "10000000000000000000000",
        "denom": "aethel"
      },

      "votes": {
        "token_house": {
          "yes": "50000000000000000000000000",
          "no": "10000000000000000000000000",
          "abstain": "5000000000000000000000000",
          "no_with_veto": "1000000000000000000000000"
        },
        "sovereign_house": {
          "yes": 65,
          "no": 20,
          "abstain": 10,
          "no_with_veto": 5
        }
      }
    }
  ]
}
```

---

### Submit Proposal

```http
POST /v1/governance/proposals
```

---

### Vote on Proposal

```http
POST /v1/governance/proposals/{proposal_id}/vote
```

**Request Body:**

```json
{
  "voter": "aethelred1abc...",
  "option": "YES"
}
```

---

## 8. Utilities

### Get Network Status

```http
GET /v1/status
```

**Response:**

```json
{
  "network": {
    "chain_id": "aethelred-mainnet-1",
    "block_height": 1234567,
    "block_time": "2026-02-08T12:00:00Z",
    "sync_status": "SYNCED"
  },

  "consensus": {
    "validators_active": 100,
    "validators_jailed": 2,
    "total_stake": "100000000000000000000000000"
  },

  "compute": {
    "jobs_pending": 45,
    "jobs_running": 120,
    "jobs_completed_24h": 45000,
    "avg_latency_ms": 52
  },

  "economics": {
    "total_supply": "1000000000000000000000000000",
    "circulating_supply": "600000000000000000000000000",
    "staked_ratio": 0.60,
    "base_fee": "100000000000000000",
    "burn_rate_24h": "50000000000000000000000"
  }
}
```

---

### Get Gas Prices

```http
GET /v1/gas-prices
```

**Response:**

```json
{
  "base_fee": "100000000000000000",
  "priority_fee": {
    "low": "10000000000000000",
    "medium": "50000000000000000",
    "high": "100000000000000000"
  },
  "gas_prices": {
    "aethel": "100000000"
  },
  "block_utilization": 0.45,
  "congestion_level": "NORMAL"
}
```

---

## Error Responses

All errors follow a consistent format:

```json
{
  "error": {
    "code": "INSUFFICIENT_BALANCE",
    "message": "Account has insufficient balance to pay for transaction",
    "details": {
      "required": "1000000000000000000",
      "available": "500000000000000000"
    },
    "request_id": "req-abc123"
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_REQUEST` | 400 | Malformed request |
| `UNAUTHORIZED` | 401 | Invalid or missing signature |
| `FORBIDDEN` | 403 | Action not allowed |
| `NOT_FOUND` | 404 | Resource not found |
| `INSUFFICIENT_BALANCE` | 402 | Not enough tokens |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |
| `SERVICE_UNAVAILABLE` | 503 | Network unavailable |

---

## Rate Limits

| Endpoint Category | Limit | Window |
|-------------------|-------|--------|
| Read (public) | 100 | 10 seconds |
| Read (authenticated) | 500 | 10 seconds |
| Write | 20 | 10 seconds |
| Heavy queries | 10 | 60 seconds |

---

<p align="center">
  <em>© 2026 Aethelred Protocol Foundation. All Rights Reserved.</em>
</p>
