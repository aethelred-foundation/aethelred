package types_test

import (
	"fmt"
	"time"

	"github.com/aethelred/aethelred/crypto/pqc"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

// ExampleVerifySealQuorum demonstrates how an external party (an auditor or an
// enterprise integrator) verifies a Digital Seal's validator quorum OFFLINE,
// without running a node.
//
// The verifier needs three things, all fetchable from the chain:
//  1. the seal's canonical claim — (chainID, jobID, model/input/output
//     commitments) — reconstructed from the seal itself;
//  2. the seal's quorum signatures — from the pouw `SealQuorum` query
//     (REST: /aethelred/pouw/v1/seals/{seal_id}/quorum);
//  3. each validator's registered hybrid public key and voting power.
//
// It then calls VerifySealQuorum, which checks that a 2/3+ power quorum of
// registered validators produced valid hybrid (secp256k1 + ML-DSA) signatures
// over the claim — verifying each signature against the validator's REGISTERED
// key, so a forged embedded key cannot inflate the quorum.
func ExampleVerifySealQuorum() {
	// (1) The claim the seal certifies. In practice this is read off the seal.
	claim := sealtypes.SealClaim{
		ChainID:          "aethelred-testnet-1",
		JobID:            "job-42",
		ModelCommitment:  make([]byte, 32),
		InputCommitment:  make([]byte, 32),
		OutputCommitment: make([]byte, 32),
	}
	signingBytes := claim.SigningBytes()

	// (3) The registered validator set: address -> {hybrid public key, power}.
	// (2) The seal's quorum signatures, as returned by the SealQuorum query.
	validators := map[string]sealtypes.ValidatorVotingInfo{}
	var quorumSigs []sealtypes.SealSignature

	// Four validators of equal power; three of them signed this seal.
	for i := 0; i < 4; i++ {
		w, _ := pqc.NewDualKeyWallet(pqc.DilithiumLevel3)
		addr := fmt.Sprintf("aethelvaloper1example%02d", i)
		validators[addr] = sealtypes.ValidatorVotingInfo{
			HybridPubKey: w.HybridPublicKey(),
			Power:        10,
		}
		if i < 3 {
			sig, _ := w.SignHybrid(signingBytes)
			quorumSigs = append(quorumSigs, sealtypes.NewValidatorSealSignature(
				addr, w.HybridPublicKey(), sig, time.Unix(0, 0).UTC(),
			))
		}
	}

	// Verify the power-weighted quorum (2/3 threshold).
	result, err := sealtypes.VerifySealQuorum(claim, quorumSigs, validators, 67)
	if err != nil {
		panic(err)
	}

	fmt.Printf("quorum reached: %v (agreed %d of %d power, %d valid signers)\n",
		result.Reached, result.AgreedPower, result.TotalPower, len(result.ValidSigners))
	// Output:
	// quorum reached: true (agreed 30 of 40 power, 3 valid signers)
}
