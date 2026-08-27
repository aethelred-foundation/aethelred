package keeper

import (
	"github.com/aethelred/aethelred/crypto/pqc"
	"github.com/aethelred/aethelred/x/seal/types"
)

// HybridSealSignatureVerifier cryptographically verifies a validator-quorum
// hybrid (secp256k1 + ML-DSA) seal signature against the seal's canonical claim.
//
// Wire it into VerificationConfig.EnhancedSignatureVerifier so the seal verifier
// performs real cryptographic verification of quorum signatures instead of the
// insecure structural-only fallback:
//
//	cfg.EnhancedSignatureVerifier = keeper.HybridSealSignatureVerifier
//
// It returns false for signatures whose algorithm is not the hybrid quorum
// algorithm — callers that mix signature types must compose verifiers per
// algorithm.
//
// NOTE: this verifies each signature against the public key embedded in the
// signature, confirming the signature is internally valid over the claim. The
// authoritative *power-weighted quorum against on-chain REGISTERED validator
// keys* is enforced separately by the pouw module's VerifyJobSealQuorum; this
// hook is a defense-in-depth cryptographic check at the seal layer (which cannot
// import the validator registry without a dependency cycle).
func HybridSealSignatureVerifier(sig types.SealSignature, seal *types.EnhancedDigitalSeal) bool {
	if seal == nil || sig.Algorithm != types.HybridSignatureAlgorithm {
		return false
	}
	ok, err := pqc.VerifyHybrid(sig.PublicKey, seal.SealClaim().SigningBytes(), sig.Signature)
	return err == nil && ok
}
