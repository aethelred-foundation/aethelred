package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/aethelred/aethelred/crypto/pqc"
)

// Domain separator and algorithm tag for validator-quorum seal signatures.
const (
	// SealClaimDomain domain-separates the seal claim from any other signed
	// message in the system.
	SealClaimDomain = "aethelred-seal-claim-v1"

	// HybridSignatureAlgorithm labels a composite secp256k1 + ML-DSA signature.
	HybridSignatureAlgorithm = "hybrid-secp256k1-mldsa"

	// SealSignerTypeValidator marks a SealSignature produced by a consensus
	// validator (as opposed to an authority or user).
	SealSignerTypeValidator = "validator"
)

// SealClaim is the canonical, committed assertion that a Digital Seal makes:
// "on chain C, compute job J over model M and input I produced output O". It is
// exactly the data each validator attests to in its vote extension, and it is
// reproducible from the finished seal — which is why a validator's signature
// over the claim is a signature over the seal's core meaning, even though the
// validator signs before the seal object exists.
//
// Block height is deliberately NOT part of the claim: a validator signs at its
// ExtendVote height, but the seal is finalized at a later completion height, so
// including height would make the validator-side and seal-side claims disagree.
// The job ID already uniquely identifies the computation (a job is sealed once),
// so it provides anti-replay without a height. Height remains available as seal
// provenance metadata, just not as part of the signed assertion.
type SealClaim struct {
	ChainID          string
	JobID            string
	ModelCommitment  []byte
	InputCommitment  []byte
	OutputCommitment []byte
}

// SigningBytes returns the canonical, length-prefixed encoding of the claim.
// This is the message validators sign and verifiers check; it is deterministic
// and collision-resistant across field boundaries.
func (c SealClaim) SigningBytes() []byte {
	var buf bytes.Buffer
	writeLP := func(b []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		buf.Write(l[:])
		buf.Write(b)
	}

	buf.WriteString(SealClaimDomain)
	writeLP([]byte(c.ChainID))
	writeLP([]byte(c.JobID))
	writeLP(c.ModelCommitment)
	writeLP(c.InputCommitment)
	writeLP(c.OutputCommitment)

	return buf.Bytes()
}

// SealClaim extracts the canonical claim from a finished enhanced seal.
func (s *EnhancedDigitalSeal) SealClaim() SealClaim {
	return SealClaim{
		ChainID:          s.ChainID,
		JobID:            s.JobID,
		ModelCommitment:  s.ModelCommitment,
		InputCommitment:  s.InputCommitment,
		OutputCommitment: s.OutputCommitment,
	}
}

// NewValidatorSealSignature constructs a SealSignature for a validator's hybrid
// signature over a SealClaim.
func NewValidatorSealSignature(validatorAddr string, hybridPubKey, hybridSig []byte, ts time.Time) SealSignature {
	return SealSignature{
		SignerAddress: validatorAddr,
		SignerType:    SealSignerTypeValidator,
		Algorithm:     HybridSignatureAlgorithm,
		PublicKey:     hybridPubKey,
		Signature:     hybridSig,
		Timestamp:     ts,
	}
}

// ValidatorVotingInfo is the registered hybrid public key and voting power of a
// validator, used to verify a seal's quorum.
type ValidatorVotingInfo struct {
	HybridPubKey []byte
	Power        int64
}

// SealQuorumResult reports the outcome of quorum verification.
type SealQuorumResult struct {
	// Reached is true when AgreedPower >= RequiredPower.
	Reached bool
	// AgreedPower is the total voting power of validators with a valid signature.
	AgreedPower int64
	// TotalPower is the total voting power of the registered validator set.
	TotalPower int64
	// RequiredPower is the power threshold for quorum.
	RequiredPower int64
	// ValidSigners lists the addresses whose hybrid signatures verified.
	ValidSigners []string
}

// VerifySealQuorum verifies that a power-weighted quorum of registered
// validators produced valid hybrid signatures over the seal's canonical claim.
//
// Each signature is verified against the validator's *registered* hybrid public
// key (not the key embedded in the signature) so a forged embedded key cannot
// inflate the quorum. Signatures from unknown signers, with the wrong type, or
// that fail verification are ignored; each validator is counted at most once.
//
// requiredPower follows the consensus convention (totalPower*pct/100)+1.
func VerifySealQuorum(claim SealClaim, sigs []SealSignature, validators map[string]ValidatorVotingInfo, thresholdPercent int) (SealQuorumResult, error) {
	if thresholdPercent <= 0 || thresholdPercent > 100 {
		return SealQuorumResult{}, fmt.Errorf("invalid threshold percent: %d", thresholdPercent)
	}

	msg := claim.SigningBytes()

	var totalPower int64
	for _, v := range validators {
		totalPower += v.Power
	}

	res := SealQuorumResult{TotalPower: totalPower}
	if totalPower > 0 {
		res.RequiredPower = (totalPower*int64(thresholdPercent))/100 + 1
	}

	seen := make(map[string]bool)
	for _, s := range sigs {
		if s.SignerType != SealSignerTypeValidator {
			continue
		}
		if seen[s.SignerAddress] {
			continue
		}
		info, ok := validators[s.SignerAddress]
		if !ok {
			continue
		}
		valid, err := pqc.VerifyHybrid(info.HybridPubKey, msg, s.Signature)
		if err != nil || !valid {
			continue
		}
		seen[s.SignerAddress] = true
		res.AgreedPower += info.Power
		res.ValidSigners = append(res.ValidSigners, s.SignerAddress)
	}

	res.Reached = res.RequiredPower > 0 && res.AgreedPower >= res.RequiredPower
	return res, nil
}
