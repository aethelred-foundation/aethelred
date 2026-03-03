# Genesis Sprint: Internal Hackathon

**Objective**: Dogfooding - Force the engineering team to build on top of Aethelred to expose bugs in the SDK and Node logic.

**Timeline**: 3 Days (Wednesday - Friday)

**Participants**: 30 Engineers broken into 5 mixed squads (Rust Core + Python SDK devs)

---

## Overview

The Genesis Sprint is an internal hackathon designed to stress-test the Aethelred platform before external launch. Teams will build real applications that push the boundaries of our Proof-of-Useful-Work, Compliance, and Bridge infrastructure.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ GENESIS SPRINT STRUCTURE │
├─────────────────────────────────────────────────────────────────────────────┤
│ │
│ Day 1 (Wednesday) │
│ ├── 9:00 AM - Kickoff & Track Assignments │
│ ├── 10:00 AM - Team Formation & Planning │
│ ├── 12:00 PM - Lunch & Architecture Review │
│ └── 1:00 PM - Hacking Begins │
│ │
│ Day 2 (Thursday) │
│ ├── All Day - Hacking │
│ ├── 4:00 PM - Progress Check-in │
│ └── 6:00 PM - Optional: Late Night Session │
│ │
│ Day 3 (Friday) │
│ ├── 9:00 AM - Final Hacking │
│ ├── 3:00 PM - Code Freeze │
│ ├── 4:00 PM - Demo Presentations (15 min each) │
│ └── 6:00 PM - Judging & Awards │
│ │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Track 1: The Compliance Breaker (Security)

**Prize**: $500 Bonus

### Objective

Bypass the ComplianceController. Try to upload a valid AI job containing "hidden" PII that the compliance module misses.

### Challenge Details

The Aethelred Compliance Module uses multiple detection mechanisms:
1. Bloom filter for sanctions screening
2. PII pattern matching (SSN, emails, phone numbers)
3. DID-based certification verification
4. Jurisdiction-based data residency rules

Your goal is to find edge cases that slip through.

### Attack Vectors to Explore

```python
# Example: Hidden SSN in image metadata
from aethelred import AethelredClient
from PIL import Image
import piexif

def hide_ssn_in_image():
 """Attempt to hide SSN in EXIF metadata"""
 img = Image.new('RGB', (100, 100))

 # Embed SSN in EXIF UserComment
 exif_dict = {
 "0th": {},
 "Exif": {
 piexif.ExifIFD.UserComment: b"SSN:123-45-6789"
 }
 }
 exif_bytes = piexif.dump(exif_dict)

 # Save and submit
 img.save("hidden_pii.jpg", exif=exif_bytes)

 # Now try to submit this as input to an AI job
 client = AethelredClient(endpoint="https://rpc.devnet.aethelred.org")

 job = client.submit_job(
 model_id="image-classifier-v1",
 input_file="hidden_pii.jpg",
 compliance={"standards": ["CCPA"]}
 )

 return job.id

# Example: Unicode homoglyph attack
def homoglyph_ssn():
 """Use lookalike characters to bypass pattern matching"""
 # Real SSN: 123-45-6789
 # Using Cyrillic 'а' instead of Latin 'a', etc.
 fake_ssn = "１２３-４５-６７８９" # Full-width digits

 return {
 "applicant_id": "USER001",
 "tax_id": fake_ssn # Will this be caught?
 }

# Example: Base64 encoded PII
def encoded_pii():
 """Encode PII in a way that might bypass text scanning"""
 import base64

 ssn = "123-45-6789"
 encoded = base64.b64encode(ssn.encode()).decode()

 return {
 "user_data": encoded, # "MTIzLTQ1LTY3ODk="
 "encoding": "base64"
 }
```

### Success Criteria

- Document any bypass that allows PII to reach the compute layer
- Provide a reproducible test case
- Suggest a fix for the vulnerability

### Deliverables

1. A script that demonstrates the bypass
2. Documentation of the vulnerability
3. Proposed patch to `crates/vm/src/system_contracts/compliance.rs`

---

## Track 2: The Decentralized Radiologist (Product)

**Prize**: $1000 Bonus + Demo at Mount Sinai

### Objective

Build a full E2E demo for healthcare AI verification. A web app where a doctor uploads an X-Ray, the Aethelred network runs a tumor detection model inside an SGX enclave, and returns the result with a verifiable "Proof of Hardware" certificate.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ DECENTRALIZED RADIOLOGIST │
├─────────────────────────────────────────────────────────────────────────────┤
│ │
│ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ │
│ │ Web Frontend │────►│ Backend API │────►│ Aethelred │ │
│ │ (React/Next) │ │ (FastAPI) │ │ Network │ │
│ └─────────────────┘ └─────────────────┘ └─────────────────┘ │
│ │ │ │ │
│ │ │ │ │
│ ▼ ▼ ▼ │
│ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ │
│ │ 1. Upload │ │ 2. HIPAA Check │ │ 3. TEE Compute │ │
│ │ X-Ray │ │ + BAA │ │ (SGX) │ │
│ │ Image │ │ Verify │ │ │ │
│ └─────────────────┘ └─────────────────┘ └─────────────────┘ │
│ │ │
│ ▼ │
│ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ │
│ │ 6. Display │◄────│ 5. Verify │◄────│ 4. Return │ │
│ │ Result + │ │ Attestation │ │ Result + │ │
│ │ Certificate │ │ On-Chain │ │ Proof │ │
│ └─────────────────┘ └─────────────────┘ └─────────────────┘ │
│ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Implementation Guide

#### 1. Frontend (React/Next.js)

```typescript
// pages/diagnose.tsx
import { useState } from 'react';
import { AethelredClient } from '@aethelred/sdk';

export default function DiagnosePage() {
 const [image, setImage] = useState<File | null>(null);
 const [result, setResult] = useState<DiagnosisResult | null>(null);
 const [verificationStatus, setVerificationStatus] = useState<string>('');

 const handleUpload = async () => {
 if (!image) return;

 const client = new AethelredClient({
 endpoint: process.env.NEXT_PUBLIC_AETHELRED_RPC!,
 apiKey: process.env.NEXT_PUBLIC_API_KEY!,
 });

 // Submit HIPAA-compliant job
 const job = await client.submitJob({
 modelId: 'tumor-detection-resnet50',
 inputFile: image,
 config: {
 verification: 'TEE',
 teeType: 'SGX',
 compliance: {
 standards: ['HIPAA'],
 requireBAA: true,
 auditTrail: true,
 },
 priority: 'HIGH',
 },
 });

 // Wait for result
 const diagnosis = await client.waitForResult(job.id, {
 timeout: 60000,
 onProgress: (status) => setVerificationStatus(status),
 });

 setResult(diagnosis);
 };

 return (
 <div className="container">
 <h1>Decentralized Radiologist</h1>

 <div className="upload-section">
 <input
 type="file"
 accept="image/dicom,image/png,image/jpeg"
 onChange={(e) => setImage(e.target.files?.[0] || null)}
 />
 <button onClick={handleUpload} disabled={!image}>
 Analyze X-Ray
 </button>
 </div>

 {verificationStatus && (
 <div className="status">
 Status: {verificationStatus}
 </div>
 )}

 {result && (
 <div className="result">
 <h2>Diagnosis Result</h2>
 <p>Finding: {result.output.diagnosis}</p>
 <p>Confidence: {result.output.confidence}%</p>

 <div className="verification">
 <h3>Proof of Hardware Certificate</h3>
 <p>TEE Type: {result.teeAttestation.type}</p>
 <p>Measurement: {result.teeAttestation.mrenclave}</p>
 <p>Verified On-Chain: {result.proofTxHash}</p>

 <a
 href={`https://explorer.aethelred.org/tx/${result.proofTxHash}`}
 target="_blank"
 >
 View Proof on Aethelred Explorer →
 </a>
 </div>
 </div>
 )}
 </div>
 );
}
```

#### 2. Backend API (FastAPI)

```python
# backend/main.py
from fastapi import FastAPI, UploadFile, HTTPException
from aethelred import AethelredClient
from aethelred.compliance import HIPAAChecker

app = FastAPI()

client = AethelredClient(
 endpoint="https://rpc.testnet.aethelred.org",
 api_key=os.environ["AETHELRED_API_KEY"]
)

@app.post("/api/diagnose")
async def diagnose_xray(
 image: UploadFile,
 patient_id: str,
 physician_id: str,
 institution_id: str,
):
 # 1. Verify HIPAA compliance
 hipaa = HIPAAChecker(client)

 # Check if physician has valid HIPAA certification
 if not await hipaa.verify_certification(physician_id):
 raise HTTPException(400, "Physician lacks HIPAA certification")

 # Check if BAA exists between institution and Aethelred
 if not await hipaa.verify_baa(institution_id):
 raise HTTPException(400, "No BAA on file")

 # 2. Submit job with full audit trail
 job = await client.submit_job(
 model_id="tumor-detection-resnet50",
 input_data={
 "image": await image.read(),
 "format": image.content_type,
 },
 config={
 "verification": "TEE",
 "tee_type": "SGX",
 "compliance": {
 "standards": ["HIPAA"],
 "phi_handling": "encrypted",
 "audit_trail": True,
 },
 "metadata": {
 "patient_id_hash": hash_patient_id(patient_id),
 "physician_id": physician_id,
 "institution_id": institution_id,
 "timestamp": datetime.utcnow().isoformat(),
 },
 },
 )

 # 3. Wait for verified result
 result = await client.wait_for_result(job.id, timeout=60)

 # 4. Generate audit certificate
 certificate = await client.generate_audit_certificate(
 job_id=job.id,
 include_tee_attestation=True,
 include_compliance_proof=True,
 )

 return {
 "diagnosis": result.output,
 "proof": {
 "tx_hash": result.proof_tx_hash,
 "tee_attestation": result.tee_attestation,
 "certificate": certificate,
 },
 }
```

### Success Criteria

- Working web app that accepts X-ray uploads
- Tumor detection result with confidence score
- Verifiable TEE attestation (SGX quote)
- On-chain proof transaction
- HIPAA audit trail

### Deliverables

1. GitHub repo with frontend + backend
2. Docker compose for local deployment
3. 5-minute demo video
4. Documentation for Mount Sinai integration

---

## Track 3: The Quantum Panic (Core)

**Prize**: $750 Bonus

### Objective

Simulate a "Q-Day" event where ECDSA is broken. Build a script that automates the mass-migration of 10,000 wallets to Dilithium-only mode in under 10 minutes.

### Context

Aethelred uses a dual-key system:
- ECDSA (secp256k1) for current security
- Dilithium3 (NIST PQC) for quantum resistance

When quantum computers break ECDSA, we need to rapidly migrate all accounts.

### Implementation

```python
# scripts/quantum_panic.py
"""
Q-Day Migration Script

Simulates a quantum emergency where ECDSA is compromised.
Migrates 10,000 wallets to Dilithium-only mode.
"""

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from aethelred import AethelredClient
from aethelred.crypto import DualKeyWallet, DilithiumWallet

# Configuration
NUM_WALLETS = 10_000
MAX_WORKERS = 50
BATCH_SIZE = 100
TARGET_TIME_MINUTES = 10

async def migrate_wallet(client: AethelredClient, wallet: DualKeyWallet) -> bool:
 """
 Migrate a single wallet from ECDSA+Dilithium to Dilithium-only.

 Steps:
 1. Verify current ECDSA key (for auth)
 2. Generate new Dilithium-only address
 3. Transfer all assets to new address
 4. Register key rotation on-chain
 5. Mark old address as deprecated
 """
 try:
 # Step 1: Authenticate with current keys
 current_balance = await client.get_balance(wallet.ecdsa_address)

 # Step 2: Create new Dilithium-only wallet
 new_wallet = DilithiumWallet.generate()

 # Step 3: Build migration transaction
 migration_tx = await client.build_key_migration_tx(
 from_address=wallet.ecdsa_address,
 to_address=new_wallet.address,
 amount=current_balance,
 # Sign with both keys to prove ownership
 ecdsa_signature=wallet.sign_ecdsa(migration_tx.hash),
 dilithium_signature=wallet.sign_dilithium(migration_tx.hash),
 )

 # Step 4: Submit and wait for confirmation
 tx_hash = await client.submit_transaction(migration_tx)
 await client.wait_for_confirmation(tx_hash, confirmations=1)

 # Step 5: Register key deprecation
 await client.deprecate_ecdsa_key(
 address=wallet.ecdsa_address,
 reason="QUANTUM_PANIC",
 successor=new_wallet.address,
 )

 return True

 except Exception as e:
 print(f"Migration failed for {wallet.ecdsa_address}: {e}")
 return False


async def batch_migrate(
 client: AethelredClient,
 wallets: list[DualKeyWallet],
) -> tuple[int, int]:
 """Migrate a batch of wallets concurrently."""
 tasks = [migrate_wallet(client, w) for w in wallets]
 results = await asyncio.gather(*tasks, return_exceptions=True)

 success = sum(1 for r in results if r is True)
 failed = len(results) - success

 return success, failed


async def quantum_panic_drill():
 """
 Execute the Q-Day migration drill.

 Target: 10,000 wallets in 10 minutes
 Rate: ~17 wallets/second
 """
 print("=" * 60)
 print("QUANTUM PANIC DRILL INITIATED ")
 print("=" * 60)
 print(f"Target: {NUM_WALLETS} wallets in {TARGET_TIME_MINUTES} minutes")
 print()

 # Initialize client
 client = AethelredClient(
 endpoint="https://rpc.devnet.aethelred.org",
 api_key=os.environ["AETHELRED_API_KEY"],
 )

 # Generate test wallets (in production, would load from DB)
 print(f"Generating {NUM_WALLETS} test wallets...")
 wallets = [DualKeyWallet.generate() for _ in range(NUM_WALLETS)]

 # Fund wallets with test tokens
 print("Funding wallets with test tokens...")
 await client.faucet_batch([w.ecdsa_address for w in wallets])

 # Start migration
 start_time = time.time()
 total_success = 0
 total_failed = 0

 print("\nStarting migration...")
 print("-" * 60)

 # Process in batches
 for i in range(0, NUM_WALLETS, BATCH_SIZE):
 batch = wallets[i:i + BATCH_SIZE]
 batch_num = i // BATCH_SIZE + 1
 total_batches = (NUM_WALLETS + BATCH_SIZE - 1) // BATCH_SIZE

 success, failed = await batch_migrate(client, batch)
 total_success += success
 total_failed += failed

 elapsed = time.time() - start_time
 rate = total_success / elapsed if elapsed > 0 else 0
 eta = (NUM_WALLETS - total_success) / rate if rate > 0 else 0

 print(f"Batch {batch_num}/{total_batches}: "
 f"{success}/{len(batch)} migrated | "
 f"Total: {total_success}/{NUM_WALLETS} | "
 f"Rate: {rate:.1f}/s | "
 f"ETA: {eta:.0f}s")

 # Final report
 elapsed = time.time() - start_time

 print()
 print("=" * 60)
 print("MIGRATION COMPLETE")
 print("=" * 60)
 print(f"Total Wallets: {NUM_WALLETS}")
 print(f"Successful: {total_success}")
 print(f"Failed: {total_failed}")
 print(f"Success Rate: {total_success/NUM_WALLETS*100:.1f}%")
 print(f"Total Time: {elapsed:.1f}s ({elapsed/60:.1f} min)")
 print(f"Average Rate: {total_success/elapsed:.1f} wallets/sec")
 print()

 target_met = elapsed < TARGET_TIME_MINUTES * 60
 if target_met:
 print("Yes TARGET MET: Migration completed under 10 minutes!")
 else:
 print("No TARGET MISSED: Optimization needed")

 return total_success, total_failed, elapsed


if __name__ == "__main__":
 asyncio.run(quantum_panic_drill())
```

### Success Criteria

- Migrate 10,000 wallets in under 10 minutes
- Zero fund loss (all balances transferred correctly)
- All migrations verified on-chain
- Old addresses properly deprecated

### Optimization Tips

1. **Batch Transactions**: Group migrations into batches
2. **Parallel Signing**: Use thread pools for Dilithium signing (CPU-heavy)
3. **Transaction Pooling**: Pre-build transactions before submission
4. **Mempool Optimization**: Submit to multiple nodes

### Deliverables

1. Migration script with benchmarks
2. Performance optimization report
3. Failure recovery procedures
4. Integration with alerting system

---

## Judging Criteria

| Criterion | Weight | Description |
|-----------|--------|-------------|
| Technical Depth | 30% | Quality of code, architecture, and implementation |
| Innovation | 25% | Creative approaches and novel solutions |
| Completeness | 20% | Working end-to-end demo |
| Documentation | 15% | Clear docs and runnable instructions |
| Presentation | 10% | Demo quality and communication |

---

## Rules

1. All code must be pushed to the internal GitLab by 3 PM Friday
2. Teams can use any language, but must integrate with Aethelred
3. Use DevNet only - do not touch Testnet
4. Document all bugs found (they count as bonus points!)
5. Have fun and break things 

---

## Resources

- DevNet RPC: `https://rpc.devnet.aethelred.org`
- DevNet Faucet: `https://faucet.devnet.aethelred.org`
- SDK Docs: `./sdk/python/README.md`
- Slack: `#genesis-sprint`

---

**Good luck, and may the best squad win!** 
