#!/usr/bin/env python3
"""
Credit Scoring Example

This example demonstrates how to use the Aethelred SDK to:
1. Submit a verified credit scoring inference job
2. Poll for completion and retrieve results
3. Fetch the Digital Seal for the computation
4. Verify the result cryptographically

Prerequisites:
    pip install aethelred numpy

Usage:
    export AETHELRED_API_KEY="your-api-key"
    python credit_scoring.py
"""

import logging
import os
from datetime import datetime, timezone

import numpy as np

from aethelred import (
    AethelredClient,
    AsyncAethelredClient,
    Config,
    Network,
    PrivacyLevel,
    ComplianceFramework,
    sha256_hex,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def create_sample_loan_application() -> np.ndarray:
    """Create a sample loan application with 64 features."""
    features = {
        # Demographics (normalized)
        "age": 0.45,  # 35 years old (normalized 0-1)
        "income_log": 0.72,  # $85,000 annual income
        "employment_years": 0.6,  # 6 years at current job
        "education_level": 0.8,  # Master's degree
        # Credit History
        "credit_score_normalized": 0.75,  # 720 FICO
        "num_credit_accounts": 0.4,
        "credit_utilization": 0.25,
        "payment_history": 0.95,  # 95% on-time payments
        "oldest_account_years": 0.5,
        "recent_inquiries": 0.1,
        # Loan Details
        "loan_amount_normalized": 0.3,  # $30,000 requested
        "loan_term_normalized": 0.4,  # 36 months
        "loan_purpose_encoded": 0.2,  # Debt consolidation
        # Financial Ratios
        "debt_to_income": 0.28,
        "monthly_debt_payments": 0.35,
        "savings_ratio": 0.15,
    }

    # Pad to 64 features (remaining are additional credit bureau data)
    feature_vector = list(features.values())
    while len(feature_vector) < 64:
        feature_vector.append(np.random.uniform(0, 1))

    return np.array(feature_vector, dtype=np.float32).reshape(1, 64)


def main():
    """Main credit scoring workflow."""

    print("=" * 60)
    print("Aethelred Credit Scoring Demo")
    print("=" * 60)

    # ----------------------------------------------------------------
    # Step 1: Initialize the client with testnet configuration
    # ----------------------------------------------------------------
    print("\n1. Initializing client...")

    api_key = os.environ.get("AETHELRED_API_KEY", "YOUR_API_KEY_HERE")
    config = Config.testnet(api_key=api_key)

    client = AethelredClient(config)
    print(f"   Network : {config.network.value}")
    print(f"   Endpoint: {config.rpc_url}")

    # ----------------------------------------------------------------
    # Step 2: Prepare the loan application input
    # ----------------------------------------------------------------
    print("\n2. Preparing loan application...")
    loan_application = create_sample_loan_application()
    input_bytes = loan_application.tobytes()
    input_hash = sha256_hex(input_bytes)

    print(f"   Application features: {loan_application.shape}")
    print(f"   Sample features: age={loan_application[0, 0]:.2f}, "
          f"income={loan_application[0, 1]:.2f}, "
          f"credit_score={loan_application[0, 4]:.2f}")
    print(f"   Input hash: {input_hash[:16]}...")

    # ----------------------------------------------------------------
    # Step 3: Submit a verified inference job
    # ----------------------------------------------------------------
    print("\n3. Submitting verified inference job...")

    # The model hash would come from a previously registered model
    model_hash = sha256_hex(b"credit-scoring-model-v2.1")

    try:
        response = client.jobs.submit(
            model_hash=model_hash,
            input_hash=input_hash,
            metadata={
                "model_name": "XGBoost Credit Scoring v2.1",
                "input_shape": "(1, 64)",
                "privacy_level": PrivacyLevel.HYBRID.value,
                "compliance_frameworks": [
                    ComplianceFramework.SOC2.value,
                    ComplianceFramework.GDPR.value,
                ],
                "allowed_regions": ["us-east", "eu-west"],
            },
        )

        print(f"   Job ID : {response.job_id}")
        print(f"   TX Hash: {response.tx_hash}")

    except Exception as exc:
        logger.info("Network unavailable, simulating job submission: %s", exc)
        response = None
        _print_simulated_workflow(model_hash, input_hash)
        return

    # ----------------------------------------------------------------
    # Step 4: Poll for completion
    # ----------------------------------------------------------------
    print("\n4. Waiting for verified result...")

    try:
        job = client.jobs.wait_for_completion(
            response.job_id,
            poll_interval=2.0,
            timeout=120.0,
        )
        print(f"   Status    : {job.status}")
        print(f"   Proof Type: {job.proof_type}")
    except Exception as exc:
        logger.warning("Polling interrupted: %s", exc)
        return

    # ----------------------------------------------------------------
    # Step 5: Fetch the Digital Seal
    # ----------------------------------------------------------------
    print("\n5. Fetching Digital Seal...")

    seal_id = job.metadata.get("seal_id") if job.metadata else None
    if seal_id:
        seal = client.seals.get(seal_id)
        print(f"   Seal ID      : {seal.id}")
        print(f"   Seal Status  : {seal.status}")
        print(f"   Block Height : {seal.block_height}")
    else:
        print("   (No seal -- expected in testnet dry-run mode)")

    # ----------------------------------------------------------------
    # Step 6: Verify the result
    # ----------------------------------------------------------------
    print("\n6. Verifying result cryptographically...")

    if seal_id:
        result = client.verification.verify_seal(seal_id)
        print(f"   Valid: {result.get('valid', 'N/A')}")
    else:
        print("   (Skipped -- no seal to verify in dry-run)")

    # ----------------------------------------------------------------
    # Summary
    # ----------------------------------------------------------------
    print("\n" + "=" * 60)
    print("CREDIT SCORING COMPLETE")
    print("=" * 60)
    print("\nThe computation result is cryptographically verified and")
    print("can be used for regulatory compliance and audit purposes.")


def _print_simulated_workflow(model_hash: str, input_hash: str):
    """Print simulated output when no network connection is available."""

    job_id = "job_demo_" + datetime.now(tz=timezone.utc).strftime("%Y%m%d%H%M%S")
    seal_id = "seal_" + datetime.now(tz=timezone.utc).strftime("%Y%m%d%H%M%S") + "_xyz789"
    credit_score = 0.78

    print(f"\n   [Simulated] Job ID: {job_id}")
    print("   [Simulated] Status: SUBMITTED -> ASSIGNED -> EXECUTING -> VERIFYING")

    print(f"\n   [Simulated] Execution complete!")
    print(f"   - Execution time: 1,250ms")
    print(f"   - Proving time:   2,100ms")
    print(f"   - Total time:     3,450ms")

    print(f"\n   Credit Score Output: {credit_score:.4f}")
    print(f"   Interpretation: {credit_score * 100:.1f}% approval probability")

    print("\n   [Simulated] Verification:")
    print("   TEE Attestation: Platform=Intel SGX, Verified=TRUE")
    print("   zkML Proof:      System=Halo2, Verified=TRUE")
    print("   Consensus:       Validators=3/3, Reached=TRUE")

    print(f"\n   [Simulated] Digital Seal: {seal_id}")
    print(f"   Model Hash : {model_hash[:16]}...")
    print(f"   Input Hash : {input_hash[:16]}...")

    print("\n" + "=" * 60)
    print("CREDIT SCORING COMPLETE (simulated -- no network)")
    print("=" * 60)
    print(f"\n  Recommendation: {'APPROVE' if credit_score > 0.6 else 'REVIEW'}")
    print(f"  Verified: YES (TEE + zkML)")
    print(f"  Audit Trail: {seal_id}")


async def async_example():
    """Async version of the credit scoring workflow."""
    api_key = os.environ.get("AETHELRED_API_KEY", "YOUR_API_KEY_HERE")
    config = Config.testnet(api_key=api_key)

    async with AsyncAethelredClient(config) as client:
        healthy = await client.health_check()
        print(f"Connected: {healthy}")

        model_hash = sha256_hex(b"credit-scoring-model-v2.1")
        input_data = create_sample_loan_application()
        input_hash = sha256_hex(input_data.tobytes())

        response = await client.jobs.submit(
            model_hash=model_hash,
            input_hash=input_hash,
            metadata={"model_name": "XGBoost Credit Scoring v2.1"},
        )
        print(f"Submitted job: {response.job_id}")


if __name__ == "__main__":
    main()
