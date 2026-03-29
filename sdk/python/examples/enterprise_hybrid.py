"""
Enterprise Hybrid Compute Job -- The Recommended Path (Python SDK)

Demonstrates the full enterprise lifecycle:
  1. Configure enterprise client
  2. Submit a hybrid job (TEE + zkML -- the default)
  3. Poll for completion
  4. Fetch the evidence bundle
  5. Verify the audit trail
"""

import asyncio
import os

from aethelred.core.client import AsyncAethelredClient
from aethelred.core.types import ProofType


async def main() -> None:
    print("=" * 60)
    print("  Enterprise Hybrid Verification -- Python SDK")
    print("=" * 60)
    print()

    # -- Step 1: Configure enterprise client -------------------

    rpc_url = os.environ.get(
        "AETHELRED_RPC_URL", "https://rpc.testnet.aethelred.network"
    )
    api_key = os.environ.get("AETHELRED_API_KEY")

    async with AsyncAethelredClient(rpc_url, api_key=api_key) as client:
        healthy = await client.health_check()
        print(f"[1/5] Node health: {'OK' if healthy else 'UNREACHABLE'}\n")

        # -- Step 2: Submit a hybrid job (the default) ---------
        #
        # proof_type is omitted -- the SDK fills in HYBRID.

        model_hash = b"\xab\xc1\x23"  # replace with real hash
        input_hash = b"\xde\xf4\x56"  # replace with real hash

        print("[2/5] Submitting enterprise hybrid job...")
        print("      proof_type = HYBRID (TEE attestation + zkML proof)")

        response = await client.jobs.submit(
            model_hash=model_hash,
            input_hash=input_hash,
            # proof_type omitted -- defaults to HYBRID
            metadata={
                "compliance_framework": "SOC2",
                "enterprise_tier": "production",
            },
        )

        print(f"      Job ID : {response.job_id}")
        print(f"      TX Hash: {response.tx_hash}\n")

        # -- Step 3: Poll for completion -----------------------

        print("[3/5] Polling for completion (timeout 120 s)...")
        job = await client.jobs.wait_for_completion(
            response.job_id,
            poll_interval=2.0,
            timeout=120.0,
        )

        print(f"      Status     : {job.status}")
        print(f"      Proof Type : {job.proof_type}")
        print()

        # -- Step 4: Fetch the evidence bundle -----------------

        print("[4/5] Fetching evidence bundle...")
        seal_id = job.metadata.get("seal_id")
        if seal_id:
            seal = await client.seals.get(seal_id)
            print(f"      Seal ID    : {seal.id}")
            print(f"      Status     : {seal.status}")
        else:
            print("      (No seal -- expected in testnet dry-run mode)")
        print()

        # -- Step 5: Verify audit trail ------------------------

        print("[5/5] Verifying audit trail...")
        if seal_id:
            result = await client.verification.verify_seal(seal_id)
            print(f"      On-chain valid : {result.get('valid', 'N/A')}")
        else:
            print("      (Skipped -- no seal to verify in dry-run)")

    print()
    print("=" * 60)
    print("  Enterprise hybrid flow complete.")
    print()
    print("  Why HYBRID is the enterprise default:")
    print("    - TEE gives fast hardware attestation (~1 s)")
    print("    - zkML adds a mathematical proof (~30 s)")
    print("    - Together they satisfy SOC 2 / HIPAA / GDPR audits")
    print("    - The Digital Seal anchors both proofs on-chain")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
