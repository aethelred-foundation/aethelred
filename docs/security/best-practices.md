# Security Best Practices

<p align="center">
 <strong>Production Security Checklist for Aethelred</strong><br/>
 <em>Enterprise Deployment Guide</em>
</p>

---

## Document Information

| Attribute | Value |
|-----------|-------|
| **Version** | 2.0.0 |
| **Status** | Approved for Production Deployment |
| **Classification** | Confidential |
| **Last Updated** | 2026-02-08 |
| **Review Cadence** | Quarterly |

---

## Table of Contents

1. [Pre-Deployment Checklist](#1-pre-deployment-checklist)
2. [Key Management](#2-key-management)
3. [Network Security](#3-network-security)
4. [Secure Coding](#4-secure-coding)
5. [Operational Security](#5-operational-security)
6. [Incident Response](#6-incident-response)
7. [Compliance](#7-compliance)
8. [Monitoring & Alerting](#8-monitoring--alerting)

---

## 1. Pre-Deployment Checklist

### 1.1 Security Audit Status

Before deploying to production, ensure:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ PRE-DEPLOYMENT CHECKLIST │
├─────────────────────────────────────────────────────────────────────────────┤
│ │
│ □ Code Security Audit │
│ □ Third-party audit completed (NCC Group, Trail of Bits, etc.) │
│ □ All critical and high findings remediated │
│ □ Medium findings have mitigation plan │
│ □ Audit report reviewed by security team │
│ │
│ □ Smart Contract Audit (if applicable) │
│ □ Formal verification of critical paths │
│ □ Fuzzing completed with no crashes │
│ □ Gas optimization reviewed │
│ │
│ □ Infrastructure Review │
│ □ Network architecture reviewed │
│ □ Firewall rules documented and tested │
│ □ DDoS protection configured │
│ □ Secrets management verified │
│ │
│ □ Key Ceremony │
│ □ Genesis keys generated with proper entropy │
│ □ Multi-sig wallets configured │
│ □ Key backup procedures tested │
│ □ Key recovery procedures documented │
│ │
│ □ Testing │
│ □ All unit tests passing │
│ □ Integration tests completed │
│ □ Load testing performed │
│ □ Disaster recovery tested │
│ │
│ □ Documentation │
│ □ Runbooks completed │
│ □ On-call procedures documented │
│ □ Escalation paths defined │
│ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Environment Verification

```bash
# Verify SDK installation
aethel version --security-check

# Expected output:
# [OK] aethelred-cli 2.0.0
# [OK] Cryptographic libraries verified
# [OK] TLS 1.3 supported
# [OK] Post-quantum signatures available
# [OK] No known vulnerabilities

# Verify network connectivity
aethel network diagnose --network mainnet

# Expected output:
# [OK] RPC endpoint reachable (50ms latency)
# [OK] TLS certificate valid (expires in 364 days)
# [OK] Certificate chain verified
# [OK] Node version compatible
```

---

## 2. Key Management

### 2.1 Key Generation

```python
"""
Secure Key Generation Guidelines
"""

from aethelred.crypto import HybridKeyPair, SecureRandom
from aethelred.security import KeyStorage, HSMProvider
import os

# WRONG — NEVER DO THIS
# key = HybridKeyPair.from_seed(b"my-insecure-seed")

# CORRECT: Use cryptographically secure random
entropy = SecureRandom.generate(64) # 512 bits
key = HybridKeyPair.from_entropy(entropy)

# BETTER: Use hardware random number generator
with HSMProvider.connect("aws-cloudhsm://...") as hsm:
 key = hsm.generate_key_pair(
 algorithm="HYBRID_ECDSA_DILITHIUM",
 extractable=False, # Key never leaves HSM
 )
```

### 2.2 Key Storage

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ KEY STORAGE TIERS │
├─────────────────────────────────────────────────────────────────────────────┤
│ │
│ TIER 1: HOT KEYS (Transaction Signing) │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ Location: HSM or TEE-sealed storage │ │
│ │ Access: Automated systems with rate limiting │ │
│ │ Rotation: Monthly │ │
│ │ Example: Compute job submission keys │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
│ │
│ TIER 2: WARM KEYS (Validator Operations) │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ Location: HSM with multi-factor authentication │ │
│ │ Access: Operations team with approval workflow │ │
│ │ Rotation: Quarterly │ │
│ │ Example: Validator consensus keys │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
│ │
│ TIER 3: COLD KEYS (Treasury, Governance) │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ Location: Air-gapped HSM + paper backup │ │
│ │ Access: Multi-sig (3-of-5 minimum) │ │
│ │ Rotation: Never (key ceremony documented) │ │
│ │ Example: Treasury multi-sig, emergency recovery │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
│ │
│ TIER 4: BACKUP KEYS (Disaster Recovery) │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ Location: Geographically distributed (3+ locations) │ │
│ │ Access: Board-level approval + key ceremony │ │
│ │ Storage: Shamir Secret Sharing (5-of-9) │ │
│ │ Example: Genesis recovery, protocol upgrade keys │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
│ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.3 Key Rotation

```python
"""
Key Rotation Procedure
"""

from aethelred import AethelredClient
from aethelred.security import KeyRotation

client = AethelredClient(network="mainnet")

# Create rotation plan
rotation = KeyRotation(client)

# Step 1: Generate new key pair
new_key = rotation.generate_new_key(
 algorithm="HYBRID",
 store_in="aws-cloudhsm",
)

# Step 2: Register new key on-chain (multi-sig approval required)
registration_tx = rotation.register_key(
 new_key.public_key,
 effective_block=client.get_height() + 1000, # ~50 minutes
)

# Step 3: Wait for on-chain confirmation
client.wait_for_tx(registration_tx.hash)

# Step 4: Update application to use new key
rotation.switch_active_key(new_key)

# Step 5: Revoke old key (after grace period)
rotation.revoke_old_key(
 old_key_id="key-abc123",
 effective_block=client.get_height() + 10000, # ~8 hours
)
```

### 2.4 Mnemonic Handling

```python
"""
Secure Mnemonic Handling
"""

from aethelred.crypto import Mnemonic
import getpass
import gc

# WRONG — NEVER DO THIS
# mnemonic = "word1 word2 word3 ..." # Never hardcode!
# print(mnemonic) # Never print!
# log.info(f"Mnemonic: {mnemonic}") # Never log!

# CORRECT: Secure input and handling
def recover_wallet():
 # Use secure input (no echo)
 mnemonic = getpass.getpass("Enter mnemonic: ")

 try:
 # Validate and use
 wallet = Mnemonic.to_wallet(mnemonic)

 # Use wallet...

 finally:
 # Securely clear from memory
 mnemonic = "X" * len(mnemonic)
 del mnemonic
 gc.collect()

# BETTER: Use hardware wallet
from aethelred.hardware import LedgerWallet

wallet = LedgerWallet.connect()
# Mnemonic never leaves the device
tx = wallet.sign_transaction(unsigned_tx)
```

---

## 3. Network Security

### 3.1 TLS Configuration

```yaml
# production-tls.yaml
# Minimum TLS 1.3, strong cipher suites only

tls:
 min_version: "1.3"
 max_version: "1.3"

 # Only allow strong cipher suites
 cipher_suites:
 - TLS_AES_256_GCM_SHA384
 - TLS_CHACHA20_POLY1305_SHA256
 # TLS_AES_128_GCM_SHA256 allowed but not preferred

 # Certificate configuration
 certificate:
 path: "/etc/aethelred/certs/server.crt"
 key_path: "/etc/aethelred/certs/server.key"
 ca_path: "/etc/aethelred/certs/ca.crt"

 # Require client certificates for validator-to-validator
 client_auth: "require"

 # Certificate renewal
 renewal:
 auto_renew: true
 renew_before_expiry: "30d"
 acme_provider: "letsencrypt"
```

### 3.2 Firewall Rules

```bash
# Example iptables rules for validator node

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# P2P (other validators)
iptables -A INPUT -p tcp --dport 26656 -j ACCEPT

# RPC (rate limited)
iptables -A INPUT -p tcp --dport 26657 -m limit --limit 100/minute -j ACCEPT

# gRPC (internal only)
iptables -A INPUT -p tcp --dport 9090 -s 10.0.0.0/8 -j ACCEPT

# Prometheus metrics (internal only)
iptables -A INPUT -p tcp --dport 26660 -s 10.0.0.0/8 -j ACCEPT

# SSH (restricted)
iptables -A INPUT -p tcp --dport 22 -s <your-ip>/32 -j ACCEPT

# Drop everything else (implicit from policy)
```

### 3.3 DDoS Protection

```yaml
# ddos-protection.yaml

rate_limiting:
 # Per-IP limits
 ip_limits:
 requests_per_second: 50
 burst: 200

 # Per-endpoint limits
 endpoints:
 /v1/compute/jobs:
 requests_per_minute: 20
 burst: 50
 /v1/seals:
 requests_per_minute: 100
 burst: 500

# Connection limits
connections:
 max_per_ip: 100
 max_total: 10000
 idle_timeout: 60s

# Request size limits
request_limits:
 max_body_size: 10mb
 max_header_size: 8kb

# Cloudflare/AWS Shield integration
external_protection:
 enabled: true
 provider: "cloudflare"
 plan: "enterprise"
 ddos_mode: "auto"
```

---

## 4. Secure Coding

### 4.1 Input Validation

```python
"""
Input Validation Guidelines
"""

from aethelred import SovereignData
from aethelred.validation import (
 validate_address,
 validate_amount,
 validate_model_id,
 sanitize_string,
)
from pydantic import BaseModel, validator, Field
from typing import Optional


# CORRECT: Use strict validation
class CreditApplicationInput(BaseModel):
 """Validated input for credit scoring."""

 # Positive numbers only
 annual_income: float = Field(gt=0, le=10_000_000)

 # Bounded integer
 age: int = Field(ge=18, le=120)

 # Enum validation
 employment_status: str = Field(regex="^(employed|self-employed|retired)$")

 # Optional with default
 existing_debt: float = Field(default=0.0, ge=0, le=50_000_000)

 @validator("employment_status")
 def lowercase_status(cls, v):
 return v.lower()


def process_application(raw_input: dict) -> SovereignData:
 """Process credit application with validation."""
 # Validate input (raises ValidationError on failure)
 validated = CreditApplicationInput(**raw_input)

 # Convert to SovereignData
 return SovereignData(validated.dict())
```

### 4.2 Error Handling

```python
"""
Secure Error Handling
"""

from aethelred.exceptions import (
 AethelredError,
 AttestationError,
 JurisdictionViolation,
)
import logging

logger = logging.getLogger(__name__)


# WRONG — NEVER DO THIS
def bad_error_handling():
 try:
 result = process_sensitive_data(data)
 except Exception as e:
 # Never expose internal errors to users!
 return {"error": str(e), "stacktrace": traceback.format_exc()}


# CORRECT: Sanitized error responses
def good_error_handling():
 try:
 result = process_sensitive_data(data)
 return {"success": True, "result": result}

 except JurisdictionViolation as e:
 # Log full details internally
 logger.error(
 "Jurisdiction violation",
 extra={
 "error_code": e.code,
 "details": e.details, # May contain sensitive info
 "request_id": request.id,
 }
 )
 # Return sanitized message to user
 return {
 "success": False,
 "error": {
 "code": "JURISDICTION_VIOLATION",
 "message": "Data cannot be processed in the requested jurisdiction",
 "request_id": request.id, # For support reference
 }
 }

 except AethelredError as e:
 logger.error("Aethelred error", extra={"error": e})
 return {
 "success": False,
 "error": {
 "code": e.code,
 "message": e.user_message, # Pre-sanitized
 "request_id": request.id,
 }
 }

 except Exception:
 # Log everything for debugging
 logger.exception("Unexpected error processing request")
 # Return generic message
 return {
 "success": False,
 "error": {
 "code": "INTERNAL_ERROR",
 "message": "An unexpected error occurred",
 "request_id": request.id,
 }
 }
```

### 4.3 Secrets in Code

```python
"""
Secrets Management
"""

import os
from aethelred.security import SecretManager

# WRONG — NEVER DO THIS
API_KEY = "sk-1234567890abcdef" # Hardcoded secret!
DATABASE_URL = "postgres://user:password@host/db" # Credentials in code!


# CORRECT: Use environment variables with validation
def get_config():
 api_key = os.environ.get("AETHELRED_API_KEY")
 if not api_key:
 raise ValueError("AETHELRED_API_KEY environment variable required")

 if not api_key.startswith("sk-"):
 raise ValueError("Invalid API key format")

 return {"api_key": api_key}


# BETTER: Use a secrets manager
def get_config_production():
 secrets = SecretManager(
 provider="aws-secrets-manager",
 region="us-east-1",
 )

 return {
 "api_key": secrets.get("aethelred/api-key"),
 "database_url": secrets.get("aethelred/database-url"),
 "hsm_credentials": secrets.get("aethelred/hsm-creds"),
 }
```

---

## 5. Operational Security

### 5.1 Access Control

```yaml
# rbac-config.yaml

roles:
 # Read-only access for monitoring
 monitor:
 permissions:
 - "read:metrics"
 - "read:logs"
 - "read:status"

 # Developer access
 developer:
 permissions:
 - "read:*"
 - "submit:testnet-jobs"
 - "manage:own-models"

 # Operator access
 operator:
 permissions:
 - "read:*"
 - "submit:*"
 - "manage:models"
 - "restart:services"

 # Admin access
 admin:
 permissions:
 - "*"
 requires:
 - mfa: true
 - vpn: true
 - approval: "security-team"

# Access policies
policies:
 # Require MFA for sensitive operations
 mfa_required:
 - "manage:validators"
 - "manage:treasury"
 - "execute:upgrades"

 # Time-based restrictions
 time_restrictions:
 - role: "developer"
 hours: "06:00-22:00"
 timezone: "UTC"

 # IP restrictions
 ip_restrictions:
 admin:
 - "10.0.0.0/8" # Internal only
 - "<vpn-egress-ip>/32"
```

### 5.2 Audit Logging

```python
"""
Comprehensive Audit Logging
"""

from aethelred.audit import AuditLogger
from aethelred.security import hash_pii

audit = AuditLogger(
 destination="splunk://audit.company.com",
 encryption="aes-256-gcm",
)


def submit_compute_job(user_id: str, job_request: dict):
 # Log the action (with PII hashing)
 audit.log(
 event="COMPUTE_JOB_SUBMITTED",
 actor=hash_pii(user_id), # Hash PII
 resource=job_request["model_id"],
 action="CREATE",
 outcome="PENDING",
 metadata={
 "hardware_requested": job_request["hardware"],
 "jurisdiction": job_request["jurisdiction"],
 "ip_address": hash_pii(request.remote_addr),
 "user_agent": request.user_agent,
 },
 # Sensitive data excluded from logs
 # input_data=job_request["encrypted_input"], # WRONG — Never log
 )

 # Process job...

 # Log outcome
 audit.log(
 event="COMPUTE_JOB_COMPLETED",
 actor=hash_pii(user_id),
 resource=job_id,
 action="COMPLETE",
 outcome="SUCCESS",
 metadata={
 "seal_id": seal.id,
 "execution_time_ms": execution_time,
 },
 )
```

### 5.3 Change Management

```yaml
# change-management.yaml

change_process:
 # All changes require ticket
 ticket_required: true
 ticket_systems:
 - jira
 - servicenow

 # Approval requirements by change type
 approvals:
 minor: # Config changes, minor updates
 required: 1
 approvers: ["team-lead", "on-call-engineer"]

 standard: # Feature releases, dependency updates
 required: 2
 approvers: ["team-lead", "security-team"]
 testing: ["staging", "load-test"]

 major: # Protocol upgrades, breaking changes
 required: 3
 approvers: ["team-lead", "security-team", "cto"]
 testing: ["staging", "load-test", "chaos-test"]
 freeze_period: "24h"

 emergency: # Security patches, critical fixes
 required: 2
 approvers: ["security-team", "on-call-manager"]
 post_mortem: true

 # Deployment windows
 deployment_windows:
 production:
 allowed_days: ["tuesday", "wednesday", "thursday"]
 allowed_hours: "10:00-16:00"
 timezone: "UTC"
 exceptions: "emergency"

 # Rollback plan required
 rollback:
 required: true
 max_rollback_time: "15m"
 tested: true
```

---

## 6. Incident Response

### 6.1 Severity Classification

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ INCIDENT SEVERITY LEVELS │
├─────────────────────────────────────────────────────────────────────────────┤
│ │
│ SEV 1 - CRITICAL │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ • Network halted / consensus broken │ │
│ │ • Active security breach │ │
│ │ • Complete service outage │ │
│ │ • Data breach confirmed │ │
│ │ │ │
│ │ Response: Immediate all-hands, CEO notified │ │
│ │ Target Resolution: 1 hour │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
│ │
│ SEV 2 - HIGH │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ • Significant degradation (>50% capacity) │ │
│ │ • Security vulnerability discovered │ │
│ │ • Key validator offline │ │
│ │ • Attestation failures widespread │ │
│ │ │ │
│ │ Response: Security team + on-call engineering │ │
│ │ Target Resolution: 4 hours │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
│ │
│ SEV 3 - MEDIUM │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ • Partial service degradation │ │
│ │ • Single validator issues │ │
│ │ • Elevated error rates │ │
│ │ • Performance regression │ │
│ │ │ │
│ │ Response: On-call engineering │ │
│ │ Target Resolution: 24 hours │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
│ │
│ SEV 4 - LOW │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ • Minor issues, workaround available │ │
│ │ • Non-critical bug │ │
│ │ • Documentation issues │ │
│ │ │ │
│ │ Response: Normal business hours │ │
│ │ Target Resolution: 1 week │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
│ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Incident Response Playbook

```yaml
# incident-response.yaml

phases:
 detection:
 steps:
 - Receive alert or report
 - Verify incident is real (not false positive)
 - Classify severity
 - Create incident ticket
 - Notify appropriate responders

 containment:
 steps:
 - Isolate affected systems
 - Preserve evidence (logs, snapshots)
 - Implement temporary mitigations
 - Communicate to stakeholders

 eradication:
 steps:
 - Identify root cause
 - Remove threat/fix vulnerability
 - Patch affected systems
 - Verify fix effectiveness

 recovery:
 steps:
 - Restore services
 - Monitor for recurrence
 - Validate data integrity
 - Confirm normal operation

 post_incident:
 steps:
 - Conduct post-mortem (within 72h)
 - Document lessons learned
 - Update runbooks
 - Implement preventive measures
 - Share with team

# Emergency contacts
contacts:
 security_team: "+1-555-SEC-TEAM"
 on_call_manager: "+1-555-ON-CALL"
 legal: "+1-555-LEGAL"
 pr: "+1-555-COMMS"
```

---

## 7. Compliance

### 7.1 Data Protection Compliance

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ COMPLIANCE REQUIREMENTS MATRIX │
├─────────────────────────────────────────────────────────────────────────────┤
│ │
│ ┌─────────────┬─────────────┬─────────────┬─────────────┬─────────────┐ │
│ │ Requirement │ GDPR │ UAE-DPL │ HIPAA │ PCI-DSS │ │
│ ├─────────────┼─────────────┼─────────────┼─────────────┼─────────────┤ │
│ │ Encryption │ Required │ Required │ Required │ Required │ │
│ │ At Rest │ │ │ │ │ │
│ ├─────────────┼─────────────┼─────────────┼─────────────┼─────────────┤ │
│ │ Encryption │ Required │ Required │ Required │ Required │ │
│ │ In Transit │ │ │ │ │ │
│ ├─────────────┼─────────────┼─────────────┼─────────────┼─────────────┤ │
│ │ Data │ EU only │ UAE only │ N/A │ N/A │ │
│ │ Residency │ │ │ │ │ │
│ ├─────────────┼─────────────┼─────────────┼─────────────┼─────────────┤ │
│ │ Access │ Required │ Required │ Required │ Required │ │
│ │ Logging │ 30 days │ 90 days │ 6 years │ 1 year │ │
│ ├─────────────┼─────────────┼─────────────┼─────────────┼─────────────┤ │
│ │ Breach │ 72 hours │ 72 hours │ 60 days │ Immediately │ │
│ │ Notification│ │ │ │ │ │
│ ├─────────────┼─────────────┼─────────────┼─────────────┼─────────────┤ │
│ │ DPO/ │ Required │ Required │ Privacy │ QSA │ │
│ │ Officer │ │ │ Officer │ │ │
│ └─────────────┴─────────────┴─────────────┴─────────────┴─────────────┘ │
│ │
│ Aethelred Implementation: │
│ • All data encrypted with AES-256-GCM │
│ • TLS 1.3 for all communications │
│ • Jurisdiction-aware routing enforces residency │
│ • Comprehensive audit logging (7 years retention) │
│ • Automated breach detection and alerting │
│ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Audit Trail Requirements

```python
"""
Compliance Audit Trail
"""

from aethelred.compliance import AuditTrail, RetentionPolicy

# Configure retention by regulation
audit = AuditTrail(
 retention=RetentionPolicy(
 default="7y",
 regulations={
 "GDPR": "6y",
 "HIPAA": "6y",
 "SOX": "7y",
 "PCI_DSS": "1y",
 "UAE_DPL": "5y",
 }
 ),
 immutable=True, # Write-once storage
 encrypted=True,
 signed=True, # Cryptographic signatures
)

# Log compliance-relevant events
audit.log_data_access(
 subject_id=hash_pii(user_id),
 data_category="FINANCIAL",
 purpose="CREDIT_SCORING",
 legal_basis="CONSENT",
 retention="5y",
)

# Export for regulators
report = audit.export_report(
 start_date="2026-01-01",
 end_date="2026-12-31",
 regulations=["GDPR", "UAE_DPL"],
 format="pdf",
 include_signatures=True,
)
```

---

## 8. Monitoring & Alerting

### 8.1 Security Monitoring

```yaml
# security-monitoring.yaml

metrics:
 # Authentication metrics
 auth:
 - name: auth_failures
 threshold: 10
 window: 5m
 severity: high
 action: page_security

 - name: auth_success_rate
 threshold: 0.95
 comparison: below
 severity: medium

 # Cryptographic metrics
 crypto:
 - name: signature_verification_failures
 threshold: 1
 window: 1m
 severity: critical
 action: page_security

 - name: attestation_failures
 threshold: 5
 window: 10m
 severity: high

 # Rate limiting
 rate_limits:
 - name: rate_limit_exceeded
 threshold: 100
 window: 1m
 severity: medium

 - name: api_error_rate
 threshold: 0.01
 comparison: above
 severity: high

 # Network security
 network:
 - name: tls_handshake_failures
 threshold: 50
 window: 5m
 severity: high

 - name: suspicious_ip_connections
 threshold: 10
 window: 1h
 severity: high
 action: block_and_alert

alerts:
 channels:
 critical:
 - pagerduty
 - slack: "#security-critical"
 - sms: security-oncall

 high:
 - pagerduty
 - slack: "#security-alerts"

 medium:
 - slack: "#security-alerts"

 low:
 - slack: "#security-info"
```

### 8.2 Dashboard Metrics

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ SECURITY DASHBOARD METRICS │
├─────────────────────────────────────────────────────────────────────────────┤
│ │
│ AUTHENTICATION │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ • Login attempts (success/failure) │ │
│ │ • Failed authentication by IP │ │
│ │ • MFA adoption rate │ │
│ │ • Session duration distribution │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
│ │
│ CRYPTOGRAPHY │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ • Signature verification rate │ │
│ │ • Attestation freshness (time since last) │ │
│ │ • Key rotation status │ │
│ │ • Post-quantum signature adoption │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
│ │
│ NETWORK │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ • TLS version distribution │ │
│ │ • Rate limit hits by endpoint │ │
│ │ • Geographic distribution of requests │ │
│ │ • DDoS mitigation activations │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
│ │
│ COMPLIANCE │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ • Data residency violations (should be 0) │ │
│ │ • Jurisdiction routing success rate │ │
│ │ • Audit log completeness │ │
│ │ • Data retention compliance │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
│ │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ SECURITY QUICK REFERENCE │
├─────────────────────────────────────────────────────────────────────────────┤
│ │
│ DO: │
│ Yes Use hardware security modules (HSM) for key storage │
│ Yes Enable MFA for all privileged accounts │
│ Yes Encrypt all data at rest and in transit │
│ Yes Log all security-relevant events │
│ Yes Rotate keys according to schedule │
│ Yes Keep dependencies updated │
│ Yes Test disaster recovery procedures │
│ Yes Report security issues to security@aethelred.io │
│ │
│ DON'T: │
│ No Hardcode secrets in code │
│ No Log sensitive data (PII, credentials) │
│ No Disable security features for "convenience" │
│ No Skip code review for "urgent" changes │
│ No Deploy without testing │
│ No Ignore security alerts │
│ No Share credentials via chat/email │
│ No Run outdated software versions │
│ │
│ EMERGENCY CONTACTS: │
│ • Security Team: security@aethelred.io │
│ • Emergency Hotline: +1-555-SECURITY │
│ • Bug Bounty: hackerone.com/aethelred │
│ │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

<p align="center">
 <em>© 2026 Aethelred Protocol Foundation. All Rights Reserved.</em>
</p>
