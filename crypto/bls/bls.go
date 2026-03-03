// Package bls implements BLS12-381 signature aggregation for Aethelred vote extensions.
//
// BLS (Boneh-Lynn-Shacham) signatures allow N individual signatures to be
// combined into a single aggregate signature of constant size (96 bytes on G2).
// Verification of the aggregate is roughly equivalent to the cost of verifying
// a single signature, reducing on-chain data and block verification time as the
// validator set grows.
//
// This is the same scheme used by Ethereum's beacon chain for attestation aggregation.
package bls

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	bls12381 "github.com/kilic/bls12-381"
)

// Sizes for BLS12-381
const (
	PrivateKeySize = 32
	PublicKeySize  = 48  // Compressed G1 point
	SignatureSize  = 96  // Compressed G2 point
)

// Domain separation tag for Aethelred vote extension signing (RFC 9380)
var domainSeparationTag = []byte("AETHELRED-VOTE-EXT-BLS-SIG-V1")

// PrivateKey is a BLS12-381 private key (scalar in Fr)
type PrivateKey struct {
	scalar *bls12381.Fr
}

// PublicKey is a BLS12-381 public key (point on G1)
type PublicKey struct {
	point *bls12381.PointG1
}

// Signature is a BLS12-381 signature (point on G2)
type Signature struct {
	point *bls12381.PointG2
}

// AggregateSignature holds an aggregated BLS signature and the public keys
// of all signers, enabling compact on-chain storage.
type AggregateSignature struct {
	// Signature is the aggregated BLS signature (96 bytes)
	Signature []byte
	// SignerPubKeys is the list of public keys that contributed (48 bytes each)
	SignerPubKeys [][]byte
	// SignerCount is the number of validators whose signatures were aggregated
	SignerCount int
}

// GenerateKeyPair generates a new BLS12-381 key pair from cryptographic randomness.
func GenerateKeyPair() (*PrivateKey, *PublicKey, error) {
	// Generate random scalar
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	scalar := bls12381.NewFr()
	scalar.FromBytes(seed[:32])

	// Derive public key: P = scalar * G1
	g1 := bls12381.NewG1()
	pubPoint := g1.New()
	g1.MulScalarBig(pubPoint, g1.One(), scalar.ToBig())

	return &PrivateKey{scalar: scalar}, &PublicKey{point: pubPoint}, nil
}

// PrivateKeyFromBytes deserializes a private key from 32 bytes.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d", PrivateKeySize, len(b))
	}
	scalar := bls12381.NewFr()
	scalar.FromBytes(b)
	return &PrivateKey{scalar: scalar}, nil
}

// Bytes returns the 32-byte serialized private key.
func (sk *PrivateKey) Bytes() []byte {
	return sk.scalar.ToBytes()
}

// PublicKeyFromBytes deserializes a public key from 48 compressed bytes.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: expected %d, got %d", PublicKeySize, len(b))
	}
	g1 := bls12381.NewG1()
	point, err := g1.FromCompressed(b)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	return &PublicKey{point: point}, nil
}

// Bytes returns the 48-byte compressed public key.
func (pk *PublicKey) Bytes() []byte {
	g1 := bls12381.NewG1()
	return g1.ToCompressed(pk.point)
}

// SignatureFromBytes deserializes a signature from 96 compressed bytes.
func SignatureFromBytes(b []byte) (*Signature, error) {
	if len(b) != SignatureSize {
		return nil, fmt.Errorf("invalid signature size: expected %d, got %d", SignatureSize, len(b))
	}
	g2 := bls12381.NewG2()
	point, err := g2.FromCompressed(b)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}
	return &Signature{point: point}, nil
}

// Bytes returns the 96-byte compressed signature.
func (sig *Signature) Bytes() []byte {
	g2 := bls12381.NewG2()
	return g2.ToCompressed(sig.point)
}

// Sign creates a BLS signature over message using the private key.
// Uses hash-to-curve (RFC 9380) with a domain separation tag.
func Sign(sk *PrivateKey, message []byte) (*Signature, error) {
	if sk == nil || sk.scalar == nil {
		return nil, errors.New("nil private key")
	}

	// Hash message to G2 point
	g2 := bls12381.NewG2()
	msgPoint, err := g2.HashToCurve(hashWithDST(message), domainSeparationTag)
	if err != nil {
		return nil, fmt.Errorf("hash-to-curve failed: %w", err)
	}

	// Signature = sk * H(m)
	sigPoint := g2.New()
	g2.MulScalarBig(sigPoint, msgPoint, sk.scalar.ToBig())

	return &Signature{point: sigPoint}, nil
}

// Verify checks a BLS signature against a public key and message.
func Verify(pk *PublicKey, message []byte, sig *Signature) (bool, error) {
	if pk == nil || sig == nil {
		return false, errors.New("nil public key or signature")
	}

	engine := bls12381.NewEngine()
	g1 := bls12381.NewG1()
	g2 := bls12381.NewG2()

	// Hash message to G2
	msgPoint, err := g2.HashToCurve(hashWithDST(message), domainSeparationTag)
	if err != nil {
		return false, fmt.Errorf("hash-to-curve failed: %w", err)
	}

	// Verify: e(P, H(m)) == e(G1, sig)
	// Equivalent to: e(P, H(m)) * e(-G1, sig) == 1
	g1Neg := g1.New()
	g1.Neg(g1Neg, g1.One())

	engine.AddPair(pk.point, msgPoint)
	engine.AddPair(g1Neg, sig.point)

	return engine.Check(), nil
}

// AggregateSignatures combines multiple BLS signatures into one.
// The aggregate signature is 96 bytes regardless of how many signatures are combined.
func AggregateSignatures(signatures []*Signature) (*Signature, error) {
	if len(signatures) == 0 {
		return nil, errors.New("no signatures to aggregate")
	}

	g2 := bls12381.NewG2()
	aggregate := g2.New()
	aggregate.Set(signatures[0].point)

	for i := 1; i < len(signatures); i++ {
		if signatures[i] == nil {
			return nil, fmt.Errorf("nil signature at index %d", i)
		}
		g2.Add(aggregate, aggregate, signatures[i].point)
	}

	return &Signature{point: aggregate}, nil
}

// VerifyAggregate verifies an aggregate signature against multiple public keys
// and a single shared message. All signers must have signed the same message.
//
// This is the core optimization: verifying an aggregate of N signatures costs
// roughly the same as verifying 1 individual signature.
func VerifyAggregate(pubKeys []*PublicKey, message []byte, aggSig *Signature) (bool, error) {
	if len(pubKeys) == 0 {
		return false, errors.New("no public keys")
	}
	if aggSig == nil {
		return false, errors.New("nil aggregate signature")
	}

	// Aggregate public keys: P_agg = P1 + P2 + ... + Pn
	g1 := bls12381.NewG1()
	aggPubKey := g1.New()
	aggPubKey.Set(pubKeys[0].point)
	for i := 1; i < len(pubKeys); i++ {
		if pubKeys[i] == nil {
			return false, fmt.Errorf("nil public key at index %d", i)
		}
		g1.Add(aggPubKey, aggPubKey, pubKeys[i].point)
	}

	// Verify with aggregated public key
	return Verify(&PublicKey{point: aggPubKey}, message, aggSig)
}

// VerifyAggregateBytes is a convenience function that works with raw byte slices.
func VerifyAggregateBytes(pubKeyBytes [][]byte, message, sigBytes []byte) (bool, error) {
	pubKeys := make([]*PublicKey, len(pubKeyBytes))
	for i, b := range pubKeyBytes {
		pk, err := PublicKeyFromBytes(b)
		if err != nil {
			return false, fmt.Errorf("invalid public key at index %d: %w", i, err)
		}
		pubKeys[i] = pk
	}

	sig, err := SignatureFromBytes(sigBytes)
	if err != nil {
		return false, fmt.Errorf("invalid aggregate signature: %w", err)
	}

	return VerifyAggregate(pubKeys, message, sig)
}

// hashWithDST prepends the domain separation tag to the message for hash-to-curve.
func hashWithDST(message []byte) []byte {
	h := sha256.New()
	h.Write(domainSeparationTag)
	h.Write(message)
	return h.Sum(nil)
}

// Zeroize securely wipes private key material from memory.
func (sk *PrivateKey) Zeroize() {
	if sk != nil && sk.scalar != nil {
		sk.scalar.FromBytes(make([]byte, 32))
		sk.scalar = nil
	}
}
