# Getting Started with Aethelred

<p align="center">
 <strong>Your First Sovereign Function</strong><br/>
 <em>From Zero to Verified AI in 15 Minutes</em>
</p>

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Hello Sovereign World](#3-hello-sovereign-world)
4. [Understanding the Output](#4-understanding-the-output)
5. [Working with Real AI Models](#5-working-with-real-ai-models)
6. [Handling Different Jurisdictions](#6-handling-different-jurisdictions)
7. [Viewing Digital Seals](#7-viewing-digital-seals)
8. [Next Steps](#8-next-steps)

---

## 1. Prerequisites

### 1.1 System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **OS** | macOS 12+, Ubuntu 20.04+, Windows 10+ | Ubuntu 22.04 LTS |
| **Python** | 3.10+ | 3.11+ |
| **Memory** | 4 GB | 8 GB |
| **Disk** | 1 GB | 5 GB |
| **Network** | Broadband | Low-latency |

### 1.2 Required Accounts

1. **Aethelred Wallet**: You'll create one during setup
2. **Testnet Tokens**: Available via faucet (no cost)

---

## 2. Installation

### 2.1 Install the Aethelred CLI

```bash
# macOS / Linux
curl -sSL https://get.aethelred.io | bash

# Or via Homebrew (macOS)
brew install aethelred/tap/aethel

# Or via cargo (Rust users)
cargo install aethelred-cli

# Verify installation
aethel --version
# aethelred-cli 2.0.0 (rustc 1.75.0)
```

### 2.2 Install the Python SDK

```bash
# Create a virtual environment (recommended)
python -m venv aethelred-env
source aethelred-env/bin/activate # On Windows: aethelred-env\Scripts\activate

# Install the SDK
pip install aethelred

# Verify installation
python -c "import aethelred; print(aethelred.__version__)"
# 2.0.0
```

### 2.3 Create Your Wallet

```bash
# Create a new wallet
aethel account create --name developer

# Sample output:
# Yes Created account 'developer'
#
# Address: aethelred1a2b3c4d5e6f7g8h9i0j...
# Mnemonic: word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12
#
# IMPORTANT: IMPORTANT: Save your mnemonic phrase securely!
# This is the ONLY way to recover your account.
```

### 2.4 Get Testnet Tokens

```bash
# Claim tokens from the testnet faucet
aethel faucet claim --network testnet

# Sample output:
# Yes Claimed 100 tAETHEL to aethelred1a2b3c4d5e6f7g8h9i0j...
#
# Balance: 100.000000000000000000 tAETHEL
#
# Note: Testnet tokens have no monetary value.
# They refresh daily (max 100 tAETHEL per day).
```

---

## 3. Hello Sovereign World

### 3.1 Create Your First Project

```bash
# Create a new Aethelred project
aethel init hello-sovereign --template basic
cd hello-sovereign

# Project structure:
# hello-sovereign/
# ├── src/
# │ └── main.py # Your sovereign function
# ├── models/ # AI models (optional)
# ├── tests/ # Unit tests
# ├── aethelred.toml # Project configuration
# └── requirements.txt # Python dependencies
```

### 3.2 Your First Sovereign Function

Open `src/main.py` and replace its contents with:

```python
"""
Hello Sovereign World

This example demonstrates the simplest possible sovereign function.
It takes a string input and returns it uppercased.
"""

from aethelred import sovereign, SovereignData
from aethelred.types import Hardware, Jurisdiction


@sovereign(
 # Run on any available TEE hardware
 hardware=Hardware.AUTO,

 # No jurisdiction restriction for this example
 jurisdiction=Jurisdiction.GLOBAL,

 # Description for the model registry
 description="Converts text to uppercase within a TEE"
)
def hello_sovereign(data: SovereignData) -> SovereignData:
 """
 A simple sovereign function that uppercases text.

 All processing happens inside a Trusted Execution Environment (TEE).
 The input and output are encrypted in transit.

 Args:
 data: Encrypted input data (will contain a string)

 Returns:
 Encrypted output data (the uppercased string)
 """
 # Access the decrypted data inside the TEE
 text = data.access()

 # Perform the computation
 result = text.upper()

 # Return as SovereignData (automatically encrypted)
 return SovereignData(result)


# Main entry point for local testing
if __name__ == "__main__":
 # Test locally (simulated TEE)
 test_input = SovereignData("hello, sovereign world!")
 result = hello_sovereign(test_input)

 print(f"Input: {test_input.access()}")
 print(f"Output: {result.access()}")
 print(f"Seal: {result.seal_id}")
```

### 3.3 Run Locally (Simulated)

```bash
# Run in local simulation mode (no real TEE)
aethel run src/main.py --mode simulate

# Sample output:
# Starting local TEE simulator...
# Yes Loaded function: hello_sovereign
#
# Input: hello, sovereign world!
# Output: HELLO, SOVEREIGN WORLD!
# Seal: sim-1234567890abcdef
#
# IMPORTANT: Note: This ran in SIMULATION mode.
# For production, use --network testnet or mainnet.
```

### 3.4 Run on Testnet (Real TEE)

```bash
# Deploy and run on testnet
aethel run src/main.py --network testnet

# Sample output:
# Connecting to testnet-rpc.aethelred.io...
# [OK] Connected to Aethelred Testnet (Nebula)
#
# Submitting to TEE validator in Singapore...
# ⏳ Waiting for execution...
#
# Input: hello, sovereign world!
# Output: HELLO, SOVEREIGN WORLD!
#
# Yes Digital Seal created!
#
# Seal ID: aethel-seal-0x1234567890abcdef...
# Block: #1,234,567
# Validator: aethelredval1abc...
# Attestation: Intel SGX (DCAP)
#
# View seal: https://testnet.aethelred.io/seal/aethel-seal-0x1234567890abcdef
```

---

## 4. Understanding the Output

### 4.1 What Just Happened?

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ HELLO SOVEREIGN WORLD: WHAT HAPPENED │
├─────────────────────────────────────────────────────────────────────────────┤
│ │
│ 1. CODE SUBMISSION │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ Your function was compiled and submitted to the network │ │
│ │ The @sovereign decorator marked it for TEE execution │ │
│ └─────────────────────────────────────────────────────────────────┘ │
│ │ │
│ ▼ │
│ 2. VALIDATOR SELECTION │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ The network's "Useful Work Router" selected a validator │ │
│ │ Based on: hardware, location, current load, reputation │ │
│ └─────────────────────────────────────────────────────────────────┘ │
│ │ │
│ ▼ │
│ 3. TEE EXECUTION │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ Your function ran inside a Trusted Execution Environment │ │
│ │ • Input was decrypted only inside the enclave │ │
│ │ • Even the validator operator couldn't see your data │ │
│ │ • Output was encrypted before leaving the enclave │ │
│ └─────────────────────────────────────────────────────────────────┘ │
│ │ │
│ ▼ │
│ 4. ATTESTATION │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ The TEE hardware generated a cryptographic attestation │ │
│ │ This proves the computation ran on genuine Intel SGX hardware │ │
│ │ The attestation is verified by other validators │ │
│ └─────────────────────────────────────────────────────────────────┘ │
│ │ │
│ ▼ │
│ 5. CONSENSUS │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ The result was included in a block via consensus │ │
│ │ 2/3+ of validators agreed the computation was correct │ │
│ │ The block was finalized in ~3 seconds │ │
│ └─────────────────────────────────────────────────────────────────┘ │
│ │ │
│ ▼ │
│ 6. DIGITAL SEAL │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ A Digital Seal was created on-chain │ │
│ │ Contains: input hash, output hash, attestation, timestamp │ │
│ │ Immutable proof of your verified computation │ │
│ └─────────────────────────────────────────────────────────────────┘ │
│ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 The Digital Seal

Every sovereign function execution produces a **Digital Seal**. This is the core value proposition of Aethelred.

```python
from aethelred import get_seal

# Retrieve the seal for verification
seal = get_seal("aethel-seal-0x1234567890abcdef...")

print(f"Seal ID: {seal.id}")
print(f"Created: {seal.timestamp}")
print(f"Block: {seal.block_height}")
print()
print(f"Input Hash: {seal.input_commitment.hex()}")
print(f"Output Hash: {seal.output_commitment.hex()}")
print()
print(f"Hardware: {seal.attestation.hardware_type}")
print(f"Validator: {seal.validator}")
print(f"Attestation Valid: {seal.verify()}")
```

---

## 5. Working with Real AI Models

### 5.1 Credit Scoring Example

Let's build a more realistic example: a credit scoring model that runs inside a TEE.

```python
"""
Sovereign Credit Scoring

This example shows how to run an ML model on sensitive financial data
with full privacy and regulatory compliance.
"""

from aethelred import sovereign, SovereignData, SovereignTensor
from aethelred.types import Hardware, Jurisdiction, Compliance
from aethelred.models import load_model
import numpy as np


@sovereign(
 # Require high-security hardware (NVIDIA H100 Confidential Computing)
 hardware=Hardware.NVIDIA_H100_CC,

 # Data must stay in UAE
 jurisdiction=Jurisdiction.UAE,

 # Must comply with UAE data protection and GDPR
 compliance=[Compliance.UAE_DPL, Compliance.GDPR],

 # Create ZK proof for extra verification
 zk_proof=True,

 description="UAE-compliant credit scoring with ZK proof"
)
def score_credit_application(applicant_data: SovereignData) -> SovereignData:
 """
 Score a credit application using a pre-trained ML model.

 The applicant data is encrypted and only decrypted inside the TEE.
 The model weights are also encrypted and sealed to the TEE.
 A ZK proof is generated to prove correct execution.

 Args:
 applicant_data: Encrypted applicant features

 Returns:
 Credit score and confidence interval
 """
 # Load the pre-registered model (sealed to this TEE)
 model = load_model("credit-score-uae-v3", hardware=Hardware.NVIDIA_H100_CC)

 # Access decrypted applicant data
 features = applicant_data.access()

 # Convert to SovereignTensor (ensures data stays in TEE)
 tensor = SovereignTensor(
 np.array(features, dtype=np.float32),
 jurisdiction=Jurisdiction.UAE
 )

 # Run inference
 prediction = model.predict(tensor)

 # Extract score and confidence
 score = float(prediction.score)
 confidence = float(prediction.confidence)

 # Return result (automatically encrypted)
 return SovereignData({
 "credit_score": score,
 "confidence_lower": score - confidence,
 "confidence_upper": score + confidence,
 "risk_category": categorize_risk(score),
 "model_version": "credit-score-uae-v3",
 })


def categorize_risk(score: float) -> str:
 """Categorize risk based on score."""
 if score >= 750:
 return "LOW_RISK"
 elif score >= 650:
 return "MEDIUM_RISK"
 elif score >= 550:
 return "HIGH_RISK"
 else:
 return "VERY_HIGH_RISK"


if __name__ == "__main__":
 # Example applicant data (would be encrypted in production)
 applicant = {
 "annual_income": 250000,
 "employment_years": 5,
 "existing_debt": 50000,
 "payment_history_score": 0.95,
 "age": 35,
 "residence_type": "owned",
 }

 # Create sovereign data
 data = SovereignData(applicant, jurisdiction=Jurisdiction.UAE)

 # Run the scoring (on testnet)
 result = score_credit_application(data)

 print(f"Credit Score: {result.access()['credit_score']}")
 print(f"Risk Category: {result.access()['risk_category']}")
 print(f"Seal ID: {result.seal_id}")
```

### 5.2 Running the Credit Scoring Example

```bash
# Run on testnet (will find UAE-capable validator)
aethel run src/credit_scoring.py --network testnet

# Sample output:
# Connecting to testnet-rpc.aethelred.io...
# [OK] Connected to Aethelred Testnet (Nebula)
#
# Submitting to TEE validator in UAE...
# ⏳ Waiting for execution (NVIDIA H100 CC)...
# ⏳ Generating ZK proof...
#
# Credit Score: 723.5
# Risk Category: MEDIUM_RISK
#
# Yes Digital Seal created!
#
# Seal ID: aethel-seal-0xabcd1234...
# Block: #1,234,890
# Validator: aethelredval1uae...
# Hardware: NVIDIA H100 Confidential Computing
# Jurisdiction: UAE 
# Compliance: UAE-DPL, GDPR
# ZK Proof: Yes Verified
#
# View seal: https://testnet.aethelred.io/seal/aethel-seal-0xabcd1234
```

---

## 6. Handling Different Jurisdictions

### 6.1 Multi-Jurisdiction Example

```python
"""
Multi-Jurisdiction Processing

This example shows how to handle data from different jurisdictions
with appropriate routing and compliance.
"""

from aethelred import sovereign, SovereignData
from aethelred.types import Hardware, Jurisdiction, Compliance


@sovereign(
 hardware=Hardware.AUTO,
 jurisdiction=Jurisdiction.EU,
 compliance=[Compliance.GDPR],
 description="EU data processing with GDPR compliance"
)
def process_eu_data(data: SovereignData) -> SovereignData:
 """Process EU citizen data (GDPR compliant)."""
 # Data automatically routed to EU validator
 result = data.access()
 result["processed_by"] = "EU_VALIDATOR"
 return SovereignData(result, jurisdiction=Jurisdiction.EU)


@sovereign(
 hardware=Hardware.AWS_NITRO,
 jurisdiction=Jurisdiction.US,
 compliance=[Compliance.HIPAA],
 description="US healthcare data with HIPAA compliance"
)
def process_us_healthcare(data: SovereignData) -> SovereignData:
 """Process US healthcare data (HIPAA compliant)."""
 # Data automatically routed to US validator with HIPAA cert
 result = data.access()
 result["processed_by"] = "US_HIPAA_VALIDATOR"
 return SovereignData(result, jurisdiction=Jurisdiction.US)


@sovereign(
 hardware=Hardware.INTEL_SGX,
 jurisdiction=Jurisdiction.CHINA,
 compliance=[Compliance.PIPL],
 description="China data processing with PIPL compliance"
)
def process_china_data(data: SovereignData) -> SovereignData:
 """Process China citizen data (PIPL compliant)."""
 # Data automatically routed to China-based validator
 result = data.access()
 result["processed_by"] = "CHINA_VALIDATOR"
 return SovereignData(result, jurisdiction=Jurisdiction.CHINA)


# Smart routing based on data origin
def process_data(data: dict, origin: str) -> SovereignData:
 """Route data to appropriate jurisdiction handler."""
 sovereign_data = SovereignData(data)

 if origin in ["DE", "FR", "IT", "ES", "NL"]: # EU countries
 return process_eu_data(sovereign_data)
 elif origin == "US":
 return process_us_healthcare(sovereign_data)
 elif origin == "CN":
 return process_china_data(sovereign_data)
 else:
 raise ValueError(f"Unsupported jurisdiction: {origin}")
```

### 6.2 Jurisdiction Verification

```python
from aethelred import verify_jurisdiction

# Verify a seal was processed in the correct jurisdiction
seal = get_seal("aethel-seal-0x...")

# This will raise an error if the seal was created by a non-UAE validator
verify_jurisdiction(seal, expected=Jurisdiction.UAE)

print("Yes Data was processed in UAE as required")
```

---

## 7. Viewing Digital Seals

### 7.1 Block Explorer

Visit the Aethelred block explorer to view your seals:

- **Testnet**: https://testnet.aethelred.io
- **Mainnet**: https://explorer.aethelred.io

### 7.2 CLI Queries

```bash
# Get seal details
aethel seal get aethel-seal-0x1234567890abcdef

# Sample output:
# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ DIGITAL SEAL │
# ├─────────────────────────────────────────────────────────────────────────────┤
# │ │
# │ Seal ID: aethel-seal-0x1234567890abcdef... │
# │ Created: 2026-02-08T12:34:56Z │
# │ Block: #1,234,567 │
# │ │
# │ ───────────────────────────────────────────────────────────────────────── │
# │ │
# │ Input Hash: 0xabcd1234... │
# │ Output Hash: 0xef567890... │
# │ Model Hash: 0x12345678... │
# │ │
# │ ───────────────────────────────────────────────────────────────────────── │
# │ │
# │ Validator: aethelredval1abc... │
# │ Hardware: Intel SGX (Ice Lake) │
# │ Attestation: DCAP (Intel) │
# │ TCB Level: Up-to-date │
# │ │
# │ ───────────────────────────────────────────────────────────────────────── │
# │ │
# │ Jurisdiction: Singapore │
# │ Compliance: GDPR │
# │ ZK Proof: Not requested │
# │ │
# │ ───────────────────────────────────────────────────────────────────────── │
# │ │
# │ Verification: Yes VALID │
# │ │
# └─────────────────────────────────────────────────────────────────────────────┘

# Verify a seal
aethel seal verify aethel-seal-0x1234567890abcdef
# Yes Seal is valid and attestation verified

# Export audit report
aethel seal export aethel-seal-0x1234567890abcdef --format pdf
# Yes Exported to seal-audit-0x1234567890abcdef.pdf
```

### 7.3 Programmatic Verification

```python
from aethelred import AethelredClient, verify_seal

# Connect to network
client = AethelredClient(network="testnet")

# Fetch and verify seal
seal = client.get_seal("aethel-seal-0x1234567890abcdef")

# Full verification
verification = verify_seal(seal)

print(f"Signature Valid: {verification.signature_valid}")
print(f"Attestation Valid: {verification.attestation_valid}")
print(f"On-Chain: {verification.on_chain}")
print(f"Not Revoked: {verification.not_revoked}")
print(f"Overall: {verification.overall_valid}")

# Export for audit
audit_report = client.export_audit(seal.id, format="json")
with open("audit_report.json", "w") as f:
 f.write(audit_report)
```

---

## 8. Next Steps

### 8.1 Learn More

| Topic | Resource |
|-------|----------|
| Python SDK Deep Dive | [Python SDK Guide](../sdk/python.md) |
| TypeScript SDK | [TypeScript SDK Guide](../sdk/typescript.md) |
| Model Registry | [Model Registry Guide](model-registry.md) |
| Validator Setup | [Validator Guide](validator-setup.md) |
| API Reference | [REST API](../api/rest.md) |

### 8.2 Example Projects

```bash
# Clone the examples repository
git clone https://github.com/aethelred/examples.git
cd examples

# Available examples:
# ├── credit-scoring/ # Financial AI with compliance
# ├── healthcare-ml/ # HIPAA-compliant medical AI
# ├── fraud-detection/ # Real-time transaction analysis
# ├── kyc-verification/ # Identity verification
# └── llm-inference/ # Large language model hosting
```

### 8.3 Get Help

- **Discord**: https://discord.gg/aethelred
- **GitHub Issues**: https://github.com/aethelred/aethelred/issues
- **Documentation**: https://docs.aethelred.io
- **Email**: support@aethelred.io

---

<p align="center">
 <strong>Congratulations! You've completed your first sovereign computation.</strong><br/>
 <em>Welcome to the future of verifiable AI.</em>
</p>

---

<p align="center">
 <em>© 2026 Aethelred Protocol Foundation. All Rights Reserved.</em>
</p>
