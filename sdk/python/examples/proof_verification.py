#!/usr/bin/env python3
"""
Proof Verification Example

This example demonstrates how to use the Aethelred SDK to:
1. Fetch and verify Digital Seals
2. Inspect TEE attestations
3. Inspect zkML proofs
4. Understand hybrid verification (TEE + zkML)

Prerequisites:
    pip install aethelred

Usage:
    export AETHELRED_API_KEY="your-api-key"
    python proof_verification.py
"""

import logging
import os
from datetime import datetime, timezone

from aethelred import (
    AethelredClient,
    Config,
    ProofType,
    TEEAttestation,
    TEEPlatform,
    ZKMLProof,
    VerificationResult,
    sha256_hex,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. Seal Verification
# ---------------------------------------------------------------------------

def seal_verification_example(client: AethelredClient) -> None:
    """Demonstrate fetching and verifying a Digital Seal."""
    print("\n" + "=" * 50)
    print("1. Digital Seal Verification")
    print("=" * 50)

    # In production, this seal_id would come from a previous job submission
    demo_seal_id = "seal_demo_001"

    print(f"\n   Fetching seal: {demo_seal_id}")

    try:
        seal = client.seals.get(demo_seal_id)

        print(f"   Seal ID      : {seal.id}")
        print(f"   Status       : {seal.status}")
        print(f"   Proof Type   : {seal.proof_type}")
        print(f"   Block Height : {seal.block_height}")

        # Verify the seal on-chain
        print("\n   Verifying seal on-chain...")
        result = client.verification.verify_seal(demo_seal_id)
        print(f"   Valid: {result.get('valid', 'N/A')}")

    except Exception as exc:
        logger.info("Network unavailable, simulating: %s", exc)
        _print_simulated_seal_verification(demo_seal_id)


def _print_simulated_seal_verification(seal_id: str) -> None:
    """Print simulated seal verification output."""
    print(f"\n   [Simulated] Seal ID      : {seal_id}")
    print(f"   [Simulated] Status       : ACTIVE")
    print(f"   [Simulated] Proof Type   : HYBRID")
    print(f"   [Simulated] Block Height : 1,234,567")
    print(f"   [Simulated] TX Hash      : 0xabc123...def456")
    print(f"   [Simulated] Timestamp    : {datetime.now(tz=timezone.utc).isoformat()}")

    print("\n   [Simulated] Seal Commitments:")
    print(f"   - Model Hash : {sha256_hex(b'demo-model')[:16]}...")
    print(f"   - Input Hash : {sha256_hex(b'demo-input')[:16]}...")
    print(f"   - Output Hash: {sha256_hex(b'demo-output')[:16]}...")

    print("\n   [Simulated] Verification Checks:")
    print("     not_revoked          : PASS")
    print("     output_hash          : PASS")
    print("     validator_signatures : PASS (3/3)")
    print("   [Simulated] Overall: VALID")


# ---------------------------------------------------------------------------
# 2. TEE Attestation Inspection
# ---------------------------------------------------------------------------

def tee_attestation_example() -> None:
    """Demonstrate TEE attestation structure and verification concepts."""
    print("\n" + "=" * 50)
    print("2. TEE Attestation Inspection")
    print("=" * 50)

    print("\n   Supported TEE Platforms:")
    for platform in TEEPlatform:
        print(f"     - {platform.value}")

    print("\n   Intel SGX Attestation:")
    print("   When a job runs inside an SGX enclave, the attestation includes:")
    print("   - MRENCLAVE: hash of the enclave code and data")
    print("   - Report data: hash of the computation output")
    print("   - Quote signature: signed by the Intel Attestation Service")
    print("   - Certificate chain: verifiable up to Intel's root CA")

    print("\n   AMD SEV-SNP Attestation:")
    print("   - Measurement: hash of the VM image")
    print("   - SNP report: hardware-signed attestation report")
    print("   - VCEK/ASK/ARK certificate chain to AMD root")

    print("\n   AWS Nitro Attestation:")
    print("   - PCR values: Platform Configuration Registers")
    print("     PCR0 = enclave image, PCR1 = kernel, PCR2 = application")
    print("   - COSE_Sign1 document signed by the Nitro HSM")

    print("\n   Verification checks performed for all platforms:")
    checks = [
        ("signature", "Attestation signature is cryptographically valid"),
        ("certificate_chain", "Chain of trust verified to platform root CA"),
        ("measurement", "Code measurement matches expected hash"),
        ("tcb_level", "Trusted Computing Base is up-to-date"),
        ("freshness", "Attestation is not expired"),
    ]
    for name, description in checks:
        print(f"     {name:20s}: {description}")


# ---------------------------------------------------------------------------
# 3. zkML Proof Inspection
# ---------------------------------------------------------------------------

def zkml_proof_example() -> None:
    """Demonstrate zkML proof structure and verification concepts."""
    print("\n" + "=" * 50)
    print("3. zkML Proof Inspection")
    print("=" * 50)

    print("\n   Supported proof systems:")
    systems = [
        ("Groth16", "Fastest verification (~10ms), smallest proofs, trusted setup required"),
        ("PLONK", "Universal setup, good balance of proof size and speed"),
        ("Halo2", "No trusted setup, recursive proof friendly"),
        ("STARK", "Transparent (no trusted setup), quantum resistant, larger proofs"),
    ]
    for name, description in systems:
        print(f"     {name:8s}: {description}")

    print("\n   A zkML proof guarantees that:")
    print("   1. The correct model was used (model hash commitment)")
    print("   2. The correct input was processed (input hash commitment)")
    print("   3. The computation was performed faithfully (circuit satisfaction)")
    print("   4. The output is the genuine result (output hash commitment)")

    print("\n   Verification checks for zkML proofs:")
    checks = [
        ("input_hash", "Public input matches the committed input hash"),
        ("output_hash", "Public output matches the committed output hash"),
        ("model_hash", "Verification key corresponds to the registered model"),
        ("zk_format", "Proof is well-formed for the chosen proof system"),
        ("zk_proof", "Mathematical verification of the proof passes"),
    ]
    for name, description in checks:
        print(f"     {name:12s}: {description}")


# ---------------------------------------------------------------------------
# 4. Hybrid Verification
# ---------------------------------------------------------------------------

def hybrid_verification_example() -> None:
    """Demonstrate hybrid proof verification (TEE + zkML)."""
    print("\n" + "=" * 50)
    print("4. Hybrid Verification (TEE + zkML)")
    print("=" * 50)

    print(f"\n   Default proof type: {ProofType.HYBRID.value}")

    print("""
   Hybrid proofs combine TEE attestation and zkML proof
   for defense-in-depth security:

   TEE provides:
     - Hardware-based isolation and confidentiality
     - Fast execution (attestation in ~1 second)
     - Tamper-evident execution environment

   zkML provides:
     - Mathematical soundness (cannot be forged)
     - Publicly verifiable without trusted hardware
     - Permanent, replayable proof artifact

   Combined:
     - Compromise of one layer does not break security
     - Satisfies enterprise audit requirements (SOC 2, HIPAA, GDPR)
     - Digital Seal anchors both proofs on-chain""")

    print("\n   Hybrid verification checks:")
    checks = [
        ("tee_signature", "TEE attestation signature valid"),
        ("tee_measurement", "Enclave measurement matches registered model"),
        ("tee_freshness", "Attestation is recent"),
        ("zk_proof", "Zero-knowledge proof mathematically valid"),
        ("zk_hashes", "Input/output/model hashes match commitments"),
        ("consensus", "Validator quorum reached agreement"),
    ]
    for name, description in checks:
        print(f"     {name:18s}: {description}")

    print("\n   Both the TEE and zkML checks must pass for the hybrid")
    print("   verification to be considered valid.")


# ---------------------------------------------------------------------------
# 5. End-to-End Verification Workflow
# ---------------------------------------------------------------------------

def end_to_end_example(client: AethelredClient) -> None:
    """Demonstrate a complete verification workflow."""
    print("\n" + "=" * 50)
    print("5. End-to-End Verification Workflow")
    print("=" * 50)

    print("""
   Typical verification flow:

   1. Submit a compute job:
      response = client.jobs.submit(
          model_hash=model_hash,
          input_hash=input_hash,
      )

   2. Wait for completion:
      job = client.jobs.wait_for_completion(response.job_id)

   3. Retrieve the Digital Seal:
      seal = client.seals.get(job.metadata["seal_id"])

   4. Verify on-chain:
      result = client.verification.verify_seal(seal.id)

   5. Check the result:
      if result["valid"]:
          print("Computation is cryptographically verified!")
      else:
          print("Verification failed -- do not trust the result.")
    """)

    # Attempt a live verification against a known seal
    demo_seal_id = "seal_demo_001"

    try:
        result = client.verification.verify_seal(demo_seal_id)
        print(f"   Live verification result: valid={result.get('valid', 'N/A')}")
    except Exception as exc:
        logger.info("Network unavailable: %s", exc)
        print("   [Simulated] Verification result: valid=True")
        print("   [Simulated] All 6 checks passed.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    """Run all verification examples."""
    print("=" * 60)
    print("Aethelred Proof Verification Examples")
    print("=" * 60)

    api_key = os.environ.get("AETHELRED_API_KEY", "YOUR_API_KEY_HERE")
    config = Config.testnet(api_key=api_key)
    client = AethelredClient(config)

    print(f"\nNetwork : {config.network.value}")
    print(f"Endpoint: {config.rpc_url}")

    seal_verification_example(client)
    tee_attestation_example()
    zkml_proof_example()
    hybrid_verification_example()
    end_to_end_example(client)

    print("\n" + "=" * 60)
    print("Examples Complete")
    print("=" * 60)
    print("\nKey Takeaways:")
    print("  1. Digital Seals provide immutable on-chain audit trails")
    print("  2. TEE attestations prove hardware-isolated execution")
    print("  3. zkML proofs provide mathematical verification guarantees")
    print("  4. Hybrid proofs (the default) combine both for maximum security")
    print("  5. Use client.verification.verify_seal() for end-to-end checks")


if __name__ == "__main__":
    main()
