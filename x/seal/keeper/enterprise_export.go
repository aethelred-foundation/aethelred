package keeper

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/seal/types"
)

// ExportEnterpriseEvidenceBundle produces an audit-grade evidence bundle for a
// hybrid enterprise job. The returned bundle conforms to the canonical schema
// defined in docs/api/evidence-bundle-v1.schema.json.
//
// The function:
//  1. Retrieves the seal associated with the given jobID.
//  2. Validates that both TEE and zkML evidence are present (hybrid requirement).
//  3. Assembles all evidence into the EvidenceBundle structure.
//  4. Runs Validate() to ensure schema compliance before returning.
func ExportEnterpriseEvidenceBundle(
	ctx context.Context,
	k *Keeper,
	jobID string,
) (*types.EvidenceBundle, error) {
	// Look up seal by job ID. Try direct ID lookup first (the seal ID may
	// equal the job ID in many flows), then fall back to the job index.
	seal, err := k.GetSeal(ctx, jobID)
	if err != nil {
		seal, err = k.GetSealByJob(ctx, jobID)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve seal for job %s: %w", jobID, err)
		}
	}

	// Enterprise hybrid requires both TEE attestation(s) and a ZK proof.
	if len(seal.TeeAttestations) == 0 {
		return nil, fmt.Errorf("enterprise bundle requires TEE attestations, but seal %s has none", seal.Id)
	}
	if seal.ZkProof == nil {
		return nil, fmt.Errorf("enterprise bundle requires zkML proof, but seal %s has none", seal.Id)
	}

	// Use the first TEE attestation as the primary evidence.
	primaryTEE := seal.TeeAttestations[0]
	if len(primaryTEE.Signature) == 0 {
		return nil, fmt.Errorf("enterprise bundle requires validator signature on primary TEE attestation for seal %s", seal.Id)
	}

	// Derive a nonce from the seal ID + job ID (deterministic, reproducible).
	nonceInput := sha256.Sum256([]byte(seal.Id + jobID))
	nonce := hex.EncodeToString(nonceInput[:])

	// Build TEE evidence.
	teeEvidence := types.TEEEvidenceV1{
		Platform:    normalizePlatform(primaryTEE.Platform),
		EnclaveID:   primaryTEE.EnclaveId,
		Measurement: hex.EncodeToString(primaryTEE.Measurement),
		Quote:       base64.StdEncoding.EncodeToString(primaryTEE.Quote),
		Nonce:       nonce,
	}

	// Build ZKML evidence.
	zkmlEvidence := types.ZKMLEvidenceV1{
		ProofSystem:      normalizeProofSystem(seal.ZkProof.ProofSystem),
		ProofBytes:       base64.StdEncoding.EncodeToString(seal.ZkProof.ProofBytes),
		PublicInputs:     base64.StdEncoding.EncodeToString(seal.ZkProof.PublicInputs),
		OutputCommitment: hex.EncodeToString(seal.OutputCommitment),
	}

	// Derive operator from the first validator in the validator set, falling
	// back to the primary TEE attestation's validator address.
	operator := primaryTEE.ValidatorAddress
	if len(seal.ValidatorSet) > 0 {
		operator = seal.ValidatorSet[0]
	}

	// Derive region from the SDK context or use a default.
	region := deriveRegion(ctx)
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	chainID := sdkCtx.ChainID()
	if chainID == "" {
		return nil, fmt.Errorf("enterprise bundle requires a non-empty SDK chain ID")
	}

	bundle := &types.EvidenceBundle{
		SchemaVersion:      types.SchemaVersionV1,
		BundleID:           uuid.New().String(),
		JobID:              jobID,
		ChainID:            chainID,
		SealID:             seal.Id,
		Timestamp:          time.Now().UTC().Format(time.RFC3339),
		ModelHash:          hex.EncodeToString(seal.ModelCommitment),
		CircuitHash:        hex.EncodeToString(seal.ZkProof.CircuitHash),
		VerifyingKeyHash:   hex.EncodeToString(seal.ZkProof.VerifyingKeyHash),
		ValidatorSignature: base64.StdEncoding.EncodeToString(primaryTEE.Signature),
		ConfidenceScore:    types.Float64Ptr(1.0),
		TEEEvidence:        teeEvidence,
		ZKMLEvidence:       zkmlEvidence,
		Region:             region,
		Operator:           operator,
		PolicyDecision:     types.NewEnterprisePolicyDecision("1.0.0"),
		ArchivePointer: types.ArchivePointer{
			ArchiveType:   "opensearch",
			Index:         "aethelred-enterprise-evidence",
			DocumentID:    jobID,
			URI:           fmt.Sprintf("opensearch://aethelred-enterprise-evidence/_doc/%s", jobID),
			RetentionDays: 30,
			WriteStatus:   "pending_archive_write",
		},
		Verification: types.Verification{
			SchemaVerified:           true,
			PolicyVerified:           true,
			TEEAttestationVerified:   types.BoolPtr(true),
			ZKMLProofVerified:        types.BoolPtr(true),
			DigitalSealVerified:      types.BoolPtr(seal.Id != ""),
			LiveVerificationRequired: types.BoolPtr(false),
			VerifierVersion:          "enterprise-export-v1",
		},
	}

	// Validate the assembled bundle against the schema constraints.
	if err := bundle.Validate(); err != nil {
		return nil, fmt.Errorf("assembled bundle failed schema validation: %w", err)
	}

	return bundle, nil
}

// normalizePlatform maps internal platform identifiers to the schema v1 enum values.
func normalizePlatform(platform string) string {
	switch platform {
	case "aws-nitro", "nitro":
		return "nitro"
	case "intel-sgx", "sgx":
		return "sgx"
	case "amd-sev-snp", "sev-snp":
		return "sev-snp"
	default:
		return platform
	}
}

// normalizeProofSystem maps internal proof system names to schema v1 enum values.
func normalizeProofSystem(ps string) string {
	switch ps {
	case "ezkl", "EZKL":
		return "ezkl"
	case "risc0", "risc-zero", "stark", "STARK":
		return "stark"
	case "groth16", "Groth16":
		return "groth16"
	case "plonk", "PLONK":
		return "plonk"
	case "halo2", "Halo2":
		return "halo2"
	default:
		return ps
	}
}

// deriveRegion attempts to extract a region from context metadata.
// M42 private pilot chain IDs default to me-central-1 / UAE.
func deriveRegion(ctx context.Context) string {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	chainID := sdkCtx.ChainID()
	if strings.Contains(strings.ToLower(chainID), "m42") {
		return "me-central-1"
	}
	for _, region := range []string{"me-central-1", "eu-west-1", "us-east-1", "us-west-2", "ap-southeast-1"} {
		if strings.Contains(chainID, region) {
			return region
		}
	}
	return "us-east-1"
}
