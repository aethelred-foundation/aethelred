"""
Enterprise Hybrid Default Tests

Verifies that the SDK defaults proof_type to HYBRID when not specified.
"""

import pytest

from aethelred.core.types import ComputeJob, ProofType, SubmitJobRequest


class TestEnterpriseHybridDefaults:
    """Verify enterprise hybrid is the default path."""

    def test_submit_request_defaults_to_hybrid(self):
        """SubmitJobRequest should default proof_type to HYBRID."""
        req = SubmitJobRequest(
            model_hash=b"\x00" * 32,
            input_hash=b"\x00" * 32,
        )
        assert req.proof_type == ProofType.HYBRID

    def test_submit_request_allows_explicit_tee_override(self):
        """Explicit TEE override should still work."""
        req = SubmitJobRequest(
            model_hash=b"\x00" * 32,
            input_hash=b"\x00" * 32,
            proof_type=ProofType.TEE,
        )
        assert req.proof_type == ProofType.TEE

    def test_submit_request_allows_explicit_zkml_override(self):
        """Explicit ZKML override should still work."""
        req = SubmitJobRequest(
            model_hash=b"\x00" * 32,
            input_hash=b"\x00" * 32,
            proof_type=ProofType.ZKML,
        )
        assert req.proof_type == ProofType.ZKML

    def test_compute_job_default_proof_type_is_hybrid(self):
        """ComputeJob model should also default to HYBRID."""
        job = ComputeJob(
            id="test-job-1",
            creator="aethelred1abc...",
            model_hash=b"\x00" * 32,
            input_hash=b"\x00" * 32,
        )
        assert job.proof_type == ProofType.HYBRID

    def test_proof_type_hybrid_enum_value(self):
        """HYBRID should map to the expected wire format."""
        assert ProofType.HYBRID.value == "PROOF_TYPE_HYBRID"
        assert ProofType.HYBRID == "PROOF_TYPE_HYBRID"

    def test_all_proof_types_exist(self):
        """All expected proof types should be defined."""
        assert ProofType.TEE.value == "PROOF_TYPE_TEE"
        assert ProofType.ZKML.value == "PROOF_TYPE_ZKML"
        assert ProofType.HYBRID.value == "PROOF_TYPE_HYBRID"
        assert ProofType.OPTIMISTIC.value == "PROOF_TYPE_OPTIMISTIC"
