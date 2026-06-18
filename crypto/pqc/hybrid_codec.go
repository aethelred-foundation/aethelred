// Package pqc — compact byte serialization for hybrid (secp256k1 + ML-DSA)
// public keys and signatures, plus a stateless verifier.
//
// These helpers let components that do not hold a private key (e.g. on-chain
// seal verification) verify a validator's hybrid signature from registered
// public-key bytes and signature bytes alone.
//
// Wire formats:
//
//	HybridPublicKey:  [ecdsaLen:1][ecdsaPub][level:1][mldsaPub]
//	HybridSignature:  [ecdsaSig:64][level:1][mldsaSig]
//
// where ecdsaPub is a SEC1-encoded secp256k1 point (33 compressed or 65
// uncompressed), level is the Dilithium/ML-DSA level (2/3/5), and the ML-DSA
// public-key / signature lengths are determined by the level.
//
// Signing convention (matches DualKeyWallet composite): the ECDSA component
// signs SHA-256(message); the ML-DSA component signs the message directly.
package pqc

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
)

// HybridPublicKey returns the compact serialized hybrid public key for the
// wallet (secp256k1 compressed point + ML-DSA public key).
func (w *DualKeyWallet) HybridPublicKey() []byte {
	ecdsaPub := w.ECDSAPublicKey
	compressed := btcecCompress(ecdsaPub)

	level := byte(w.DilithiumKeyPair.Level)
	mldsaPub := w.DilithiumKeyPair.PublicKey

	out := make([]byte, 0, 1+len(compressed)+1+len(mldsaPub))
	out = append(out, byte(len(compressed)))
	out = append(out, compressed...)
	out = append(out, level)
	out = append(out, mldsaPub...)
	return out
}

// SignHybrid produces a compact serialized hybrid signature over msg using both
// the secp256k1 and ML-DSA keys (composite scheme).
func (w *DualKeyWallet) SignHybrid(msg []byte) ([]byte, error) {
	sig, err := w.Sign(msg, CompositeScheme)
	if err != nil {
		return nil, err
	}
	if len(sig.ECDSASignature) != 64 {
		return nil, fmt.Errorf("unexpected ECDSA signature length %d", len(sig.ECDSASignature))
	}
	if sig.DilithiumSignature == nil {
		return nil, errors.New("missing ML-DSA signature component")
	}

	out := make([]byte, 0, 64+1+len(sig.DilithiumSignature.Signature))
	out = append(out, sig.ECDSASignature...)
	out = append(out, byte(sig.DilithiumSignature.Level))
	out = append(out, sig.DilithiumSignature.Signature...)
	return out, nil
}

// VerifyHybrid verifies a compact hybrid signature over msg against a compact
// hybrid public key. Both the secp256k1 and ML-DSA components must verify.
func VerifyHybrid(pubBytes, msg, sigBytes []byte) (bool, error) {
	ecdsaPub, mldsaPub, pubLevel, err := parseHybridPublicKey(pubBytes)
	if err != nil {
		return false, err
	}
	ecdsaSig, mldsaSig, sigLevel, err := parseHybridSignature(sigBytes)
	if err != nil {
		return false, err
	}
	if pubLevel != sigLevel {
		return false, fmt.Errorf("hybrid level mismatch: pubkey %d, signature %d", pubLevel, sigLevel)
	}

	// Classical: ECDSA over SHA-256(msg), canonical low-S enforced.
	msgHash := sha256.Sum256(msg)
	if !verifyECDSACompact(ecdsaPub, msgHash[:], ecdsaSig) {
		return false, nil
	}

	// Post-quantum: ML-DSA over the raw message.
	ok, err := VerifyDilithium(mldsaPub, msg, &DilithiumSignature{Level: pubLevel, Signature: mldsaSig})
	if err != nil {
		return false, err
	}
	return ok, nil
}

// ValidateHybridPublicKey reports whether b is a well-formed compact hybrid
// public key (parseable secp256k1 point and correctly-sized ML-DSA key). It does
// not verify any signature; it is a structural check for registration.
func ValidateHybridPublicKey(b []byte) error {
	_, _, _, err := parseHybridPublicKey(b)
	return err
}

// btcecCompress returns the 33-byte compressed SEC1 encoding of an secp256k1
// public key.
func btcecCompress(pub *ecdsa.PublicKey) []byte {
	var x, y btcec.FieldVal
	x.SetByteSlice(pub.X.Bytes())
	y.SetByteSlice(pub.Y.Bytes())
	return btcec.NewPublicKey(&x, &y).SerializeCompressed()
}

func parseHybridPublicKey(b []byte) (ecdsaPub *ecdsa.PublicKey, mldsaPub []byte, level int, err error) {
	if len(b) < 1 {
		return nil, nil, 0, errors.New("hybrid public key too short")
	}
	ecdsaLen := int(b[0])
	if ecdsaLen != 33 && ecdsaLen != 65 {
		return nil, nil, 0, fmt.Errorf("invalid secp256k1 public key length %d", ecdsaLen)
	}
	if len(b) < 1+ecdsaLen+1 {
		return nil, nil, 0, errors.New("hybrid public key truncated")
	}
	pk, err := btcec.ParsePubKey(b[1 : 1+ecdsaLen])
	if err != nil {
		return nil, nil, 0, fmt.Errorf("invalid secp256k1 public key: %w", err)
	}
	level = int(b[1+ecdsaLen])
	params, err := GetDilithiumParams(level)
	if err != nil {
		return nil, nil, 0, err
	}
	mldsaPub = b[1+ecdsaLen+1:]
	if len(mldsaPub) != params.PublicKeySize {
		return nil, nil, 0, fmt.Errorf("invalid ML-DSA public key length: expected %d, got %d", params.PublicKeySize, len(mldsaPub))
	}
	return pk.ToECDSA(), mldsaPub, level, nil
}

func parseHybridSignature(b []byte) (ecdsaSig, mldsaSig []byte, level int, err error) {
	if len(b) < 64+1 {
		return nil, nil, 0, errors.New("hybrid signature too short")
	}
	ecdsaSig = b[:64]
	level = int(b[64])
	params, err := GetDilithiumParams(level)
	if err != nil {
		return nil, nil, 0, err
	}
	mldsaSig = b[65:]
	if len(mldsaSig) != params.SignatureSize {
		return nil, nil, 0, fmt.Errorf("invalid ML-DSA signature length: expected %d, got %d", params.SignatureSize, len(mldsaSig))
	}
	return ecdsaSig, mldsaSig, level, nil
}

// verifyECDSACompact verifies a 64-byte r||s secp256k1 signature over hash,
// rejecting non-canonical (high-S) signatures to prevent malleability.
func verifyECDSACompact(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	curveOrder := pub.Curve.Params().N
	halfOrder := new(big.Int).Rsh(curveOrder, 1)
	if s.Sign() == 0 || r.Sign() == 0 || s.Cmp(halfOrder) > 0 {
		return false
	}
	return ecdsa.Verify(pub, hash, r, s)
}
