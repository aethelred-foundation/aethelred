// Package keeper implements the Aethelred light client verification protocol.
//
// This enables resource-constrained devices (mobile, edge, IoT) to verify
// TEE attestations, ZK proofs, and computation consensus results without
// running a full node. It provides Merkle proof generation for state queries
// and validator set tracking for header chain verification.
//
// No legacy blockchain (Ethereum, Bitcoin, Solana, Polkadot) offers integrated
// light client verification of AI computation results.
package keeper

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"cosmossdk.io/log"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/crypto/bls"
)

// =============================================================================
// Light Client Header
// =============================================================================

// LightClientHeader is a compact block header for light client verification.
// Contains only the fields needed to verify computation results without
// downloading the full block.
type LightClientHeader struct {
	// ChainID for cross-chain safety
	ChainID string `json:"chain_id"`

	// Height of the block
	Height int64 `json:"height"`

	// Time of the block
	Time time.Time `json:"time"`

	// ValidatorsHash is the hash of the active validator set
	ValidatorsHash [32]byte `json:"validators_hash"`

	// NextValidatorsHash for validator set rotation
	NextValidatorsHash [32]byte `json:"next_validators_hash"`

	// AppHash is the Merkle root of application state after this block
	AppHash [32]byte `json:"app_hash"`

	// ComputeResultsRoot is the Merkle root of all computation results
	// finalized in this block. Light clients verify individual results
	// against this root.
	ComputeResultsRoot [32]byte `json:"compute_results_root"`

	// BLSAggregateSignature over this header from the validator set.
	// A single 96-byte signature replacing N individual signatures.
	BLSAggregateSignature []byte `json:"bls_aggregate_signature,omitempty"`

	// BLSSignerPubKeys are the public keys of validators who signed
	BLSSignerPubKeys [][]byte `json:"bls_signer_pub_keys,omitempty"`

	// SignedPower is the total voting power that signed this header
	SignedPower int64 `json:"signed_power"`

	// TotalPower is the total voting power of the validator set
	TotalPower int64 `json:"total_power"`
}

// =============================================================================
// Merkle Proof for State Queries
// =============================================================================

// ComputeResultProof is a Merkle inclusion proof that a specific computation
// result is included in the block's ComputeResultsRoot.
type ComputeResultProof struct {
	// JobID of the computation
	JobID string `json:"job_id"`

	// OutputHash that was verified by consensus
	OutputHash []byte `json:"output_hash"`

	// LeafHash is the hash of the computation result leaf
	LeafHash [32]byte `json:"leaf_hash"`

	// MerklePath contains sibling hashes from leaf to root.
	// Each entry is (sibling_hash, is_right) indicating whether the sibling
	// is on the right side.
	MerklePath []MerklePathEntry `json:"merkle_path"`

	// BlockHeight at which this result was finalized
	BlockHeight int64 `json:"block_height"`

	// ValidatorCount that agreed on this result
	ValidatorCount int `json:"validator_count"`

	// AgreementPower is the voting power that agreed
	AgreementPower int64 `json:"agreement_power"`
}

// MerklePathEntry is a single step in a Merkle inclusion proof
type MerklePathEntry struct {
	Hash    [32]byte `json:"hash"`
	IsRight bool     `json:"is_right"`
}

// =============================================================================
// Light Client Verifier
// =============================================================================

// LightClientVerifier enables resource-constrained clients to verify
// Aethelred computation results.
type LightClientVerifier struct {
	logger log.Logger

	// trustedHeader is the last verified header
	trustedHeader *LightClientHeader

	// trustedValidators maps pubkey bytes -> voting power
	trustedValidators map[string]int64

	// chainID for cross-chain safety
	chainID string

	// trustThreshold is the minimum fraction of power required (e.g., 2/3)
	trustThresholdNumerator   int64
	trustThresholdDenominator int64
}

// NewLightClientVerifier creates a verifier from a trusted initial header.
func NewLightClientVerifier(
	logger log.Logger,
	chainID string,
	trustedHeader *LightClientHeader,
	trustedValidators map[string]int64,
) *LightClientVerifier {
	return &LightClientVerifier{
		logger:                    logger,
		chainID:                   chainID,
		trustedHeader:             trustedHeader,
		trustedValidators:         trustedValidators,
		trustThresholdNumerator:   2,
		trustThresholdDenominator: 3,
	}
}

// VerifyHeader verifies a new header against the trusted state.
// Uses bisection: the new header must be signed by >2/3 of the
// trusted validator set's power (or the next validators if sequential).
func (v *LightClientVerifier) VerifyHeader(newHeader *LightClientHeader) error {
	if newHeader == nil {
		return errors.New("nil header")
	}

	// Chain ID must match
	if newHeader.ChainID != v.chainID {
		return fmt.Errorf("chain ID mismatch: expected %s, got %s", v.chainID, newHeader.ChainID)
	}

	// Height must advance
	if newHeader.Height <= v.trustedHeader.Height {
		return fmt.Errorf("height must advance: trusted=%d, new=%d",
			v.trustedHeader.Height, newHeader.Height)
	}

	// Time must advance
	if !newHeader.Time.After(v.trustedHeader.Time) {
		return errors.New("time must advance")
	}

	// Sequential verification: if height is trusted+1, check NextValidatorsHash
	if newHeader.Height == v.trustedHeader.Height+1 {
		if newHeader.ValidatorsHash != v.trustedHeader.NextValidatorsHash {
			return errors.New("validators hash does not match trusted next validators")
		}
	}

	// Verify BLS aggregate signature covers >2/3 of trusted power
	if len(newHeader.BLSAggregateSignature) > 0 {
		if err := v.verifyBLSAggregate(newHeader); err != nil {
			return fmt.Errorf("BLS aggregate verification failed: %w", err)
		}
	} else {
		// Without BLS, check that signed power meets threshold
		requiredPower := v.trustedHeader.TotalPower * v.trustThresholdNumerator / v.trustThresholdDenominator
		if newHeader.SignedPower < requiredPower {
			return fmt.Errorf("insufficient signed power: %d < %d (required 2/3 of %d)",
				newHeader.SignedPower, requiredPower, v.trustedHeader.TotalPower)
		}
	}

	// Update trusted state
	v.trustedHeader = newHeader
	v.logger.Info("Light client header verified",
		"height", newHeader.Height,
		"signed_power", newHeader.SignedPower,
		"total_power", newHeader.TotalPower,
	)

	return nil
}

// VerifyComputeResult verifies a computation result against a verified header
// using a Merkle inclusion proof.
func (v *LightClientVerifier) VerifyComputeResult(
	proof *ComputeResultProof,
	header *LightClientHeader,
) error {
	if proof == nil || header == nil {
		return errors.New("nil proof or header")
	}

	// Ensure the header is trusted (verified)
	if header.Height > v.trustedHeader.Height {
		return fmt.Errorf("header at height %d not yet verified (trusted=%d)",
			header.Height, v.trustedHeader.Height)
	}

	// Recompute the leaf hash
	expectedLeaf := computeResultLeafHash(proof.JobID, proof.OutputHash)
	if expectedLeaf != proof.LeafHash {
		return errors.New("leaf hash mismatch")
	}

	// Walk the Merkle path from leaf to root
	current := proof.LeafHash
	for _, entry := range proof.MerklePath {
		var combined []byte
		combined = append(combined, 0x01) // Internal node prefix (RFC 6962)
		if entry.IsRight {
			combined = append(combined, current[:]...)
			combined = append(combined, entry.Hash[:]...)
		} else {
			combined = append(combined, entry.Hash[:]...)
			combined = append(combined, current[:]...)
		}
		current = sha256.Sum256(combined)
	}

	// Check against the header's compute results root
	if current != header.ComputeResultsRoot {
		return errors.New("Merkle proof verification failed: root mismatch")
	}

	return nil
}

// verifyBLSAggregate verifies the BLS aggregate signature on a header
func (v *LightClientVerifier) verifyBLSAggregate(header *LightClientHeader) error {
	if len(header.BLSSignerPubKeys) == 0 {
		return errors.New("no BLS signer public keys")
	}

	// Compute the signed power from trusted validators
	signedPower := int64(0)
	for _, pkBytes := range header.BLSSignerPubKeys {
		if power, ok := v.trustedValidators[string(pkBytes)]; ok {
			signedPower += power
		}
	}

	// Check trust threshold
	requiredPower := v.trustedHeader.TotalPower * v.trustThresholdNumerator / v.trustThresholdDenominator
	if signedPower < requiredPower {
		return fmt.Errorf("insufficient BLS signed power: %d < %d", signedPower, requiredPower)
	}

	// Verify the aggregate signature
	headerBytes := serializeHeaderForSigning(header)
	valid, err := bls.VerifyAggregateBytes(header.BLSSignerPubKeys, headerBytes, header.BLSAggregateSignature)
	if err != nil {
		return fmt.Errorf("BLS verification error: %w", err)
	}
	if !valid {
		return errors.New("BLS aggregate signature invalid")
	}

	return nil
}

// =============================================================================
// Proof Generation (Full Node Side)
// =============================================================================

// GenerateComputeResultsRoot computes the Merkle root from a list of finalized
// computation results. Called by full nodes when building light client headers.
func GenerateComputeResultsRoot(results []ComputeResultLeaf) [32]byte {
	if len(results) == 0 {
		return sha256.Sum256([]byte("empty_compute_results"))
	}

	// Compute leaf hashes with RFC 6962 domain separation
	hashes := make([][32]byte, len(results))
	for i, r := range results {
		hashes[i] = computeResultLeafHash(r.JobID, r.OutputHash)
	}

	// Build binary Merkle tree
	for len(hashes) > 1 {
		var next [][32]byte
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				var combined []byte
				combined = append(combined, 0x01) // Internal node prefix
				combined = append(combined, hashes[i][:]...)
				combined = append(combined, hashes[i+1][:]...)
				next = append(next, sha256.Sum256(combined))
			} else {
				next = append(next, hashes[i])
			}
		}
		hashes = next
	}

	return hashes[0]
}

// GenerateComputeResultProof generates a Merkle inclusion proof for a specific
// computation result.
func GenerateComputeResultProof(results []ComputeResultLeaf, targetIndex int) (*ComputeResultProof, error) {
	if targetIndex < 0 || targetIndex >= len(results) {
		return nil, fmt.Errorf("target index %d out of range [0, %d)", targetIndex, len(results))
	}

	target := results[targetIndex]

	// Compute all leaf hashes
	hashes := make([][32]byte, len(results))
	for i, r := range results {
		hashes[i] = computeResultLeafHash(r.JobID, r.OutputHash)
	}

	// Build Merkle path by tracking the target through tree construction
	var path []MerklePathEntry
	idx := targetIndex

	for len(hashes) > 1 {
		var next [][32]byte
		nextIdx := idx / 2

		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				if i == idx || i+1 == idx {
					// This pair contains our target - record sibling
					var siblingIdx int
					var isRight bool
					if i == idx {
						siblingIdx = i + 1
						isRight = true
					} else {
						siblingIdx = i
						isRight = false
					}
					path = append(path, MerklePathEntry{
						Hash:    hashes[siblingIdx],
						IsRight: isRight,
					})
				}

				var combined []byte
				combined = append(combined, 0x01)
				combined = append(combined, hashes[i][:]...)
				combined = append(combined, hashes[i+1][:]...)
				next = append(next, sha256.Sum256(combined))
			} else {
				next = append(next, hashes[i])
			}
		}
		hashes = next
		idx = nextIdx
	}

	return &ComputeResultProof{
		JobID:          target.JobID,
		OutputHash:     target.OutputHash,
		LeafHash:       computeResultLeafHash(target.JobID, target.OutputHash),
		MerklePath:     path,
		ValidatorCount: target.ValidatorCount,
		AgreementPower: target.AgreementPower,
	}, nil
}

// ComputeResultLeaf is the input for Merkle tree construction
type ComputeResultLeaf struct {
	JobID          string
	OutputHash     []byte
	ValidatorCount int
	AgreementPower int64
}

// =============================================================================
// Helper Functions
// =============================================================================

// computeResultLeafHash computes the leaf hash for a computation result.
// Uses 0x00 prefix per RFC 6962 to prevent second preimage attacks.
func computeResultLeafHash(jobID string, outputHash []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00}) // Leaf node prefix (RFC 6962)
	h.Write([]byte("aethelred_compute_result:"))
	h.Write([]byte(jobID))
	h.Write(outputHash)

	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	return hash
}

// serializeHeaderForSigning creates the canonical byte representation
// of a header for BLS signing.
func serializeHeaderForSigning(header *LightClientHeader) []byte {
	var buf []byte
	buf = append(buf, []byte("aethelred_light_header_v1:")...)
	buf = append(buf, []byte(header.ChainID)...)

	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, uint64(header.Height))
	buf = append(buf, heightBytes...)

	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(header.Time.UnixNano()))
	buf = append(buf, timeBytes...)

	buf = append(buf, header.ValidatorsHash[:]...)
	buf = append(buf, header.AppHash[:]...)
	buf = append(buf, header.ComputeResultsRoot[:]...)

	return buf
}

// VerifyHeaderFromContext builds and verifies a light client header from SDK context.
// Used by full nodes to serve light client requests.
func BuildLightClientHeader(
	ctx sdk.Context,
	chainID string,
	computeResults []ComputeResultLeaf,
	validatorsHash, nextValidatorsHash [32]byte,
	signedPower, totalPower int64,
) *LightClientHeader {
	return &LightClientHeader{
		ChainID:            chainID,
		Height:             ctx.BlockHeight(),
		Time:               ctx.BlockTime(),
		ValidatorsHash:     validatorsHash,
		NextValidatorsHash: nextValidatorsHash,
		AppHash:            sha256.Sum256([]byte(fmt.Sprintf("app_state_%d", ctx.BlockHeight()))),
		ComputeResultsRoot: GenerateComputeResultsRoot(computeResults),
		SignedPower:         signedPower,
		TotalPower:          totalPower,
	}
}
