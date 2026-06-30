package pqc

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// NIST ACVP known-answer tests.
//
// These vectors are from the official NIST ACVP test suite for FIPS 204
// (ML-DSA keyGen) and FIPS 203 (ML-KEM keyGen), as bundled with
// cloudflare/circl v1.6.3:
//   - sign/mldsa/testdata/ML-DSA-keyGen-FIPS204
//   - kem/mlkem/testdata/ML-KEM-keyGen-FIPS203
//
// ML-DSA.KeyGen and ML-KEM.KeyGen are deterministic in their seed, so a known
// seed MUST reproduce a known public key. This validates that our wrapper's
// deterministic derivation and key serialization match the NIST standard, not
// merely that circl's internal implementation does. We pin SHA-256(publicKey)
// for compactness; any single-byte deviation in the derived key changes the
// digest.

type mldsaKeyGenKAT struct {
	name     string
	level    int
	seedHex  string
	pkSHA256 string
}

var mldsaKeyGenKATs = []mldsaKeyGenKAT{
	{
		name:     "ML-DSA-44",
		level:    DilithiumLevel2,
		seedHex:  "93ef2e6ef1fb08999d142abe0295482370d3f43bdb254a78e2b0d5168eca065f",
		pkSHA256: "6995b20ecd5cde41719035028a712ccf35b1adf53b913030423d9d6fa188d673",
	},
	{
		name:     "ML-DSA-65",
		level:    DilithiumLevel3,
		seedHex:  "70cefb9aed5b68e018b079da8284b9d5cad5499ed9c265ff73588005d85c225c",
		pkSHA256: "646b26b8d09dbc9e865b6a006c693a3127b065e62fab5fbe8b159c416462feb6",
	},
	{
		name:     "ML-DSA-87",
		level:    DilithiumLevel5,
		seedHex:  "38359fbcd79582cffe609e137ee2efe8a8dbcbad18ba92bb433ab4f09b49299d",
		pkSHA256: "ea374a09356e5f89be784f28f4ef938e8976cb5c4db00fbacb257663491748d4",
	},
}

func TestNISTKAT_MLDSAKeyGen(t *testing.T) {
	for _, kat := range mldsaKeyGenKATs {
		seed, err := hex.DecodeString(kat.seedHex)
		if err != nil {
			t.Fatalf("%s: bad seed hex: %v", kat.name, err)
		}
		kp, err := GenerateDilithiumKeyPairFromSeed(kat.level, seed)
		if err != nil {
			t.Fatalf("%s: keygen: %v", kat.name, err)
		}
		got := sha256.Sum256(kp.PublicKey)
		if hex.EncodeToString(got[:]) != kat.pkSHA256 {
			t.Errorf("%s: derived public key does not match NIST ACVP vector\n got  %x\n want %s",
				kat.name, got, kat.pkSHA256)
		}
	}
}

func TestNISTKAT_MLKEMKeyGen(t *testing.T) {
	// ML-KEM keyGen seed is d || z (each 32 bytes).
	const (
		dHex     = "e34a701c4c87582f42264ee422d3c684d97611f2523efe0c998af05056d693dc"
		zHex     = "a85768f3486bd32a01bf9a8f21ea938e648eae4e5448c34c3eb88820b159eedd"
		ekSHA256 = "7799c9d8eef172aa78c073514f2f039c240de8c5cb61bca82ba0bc46041ce279"
	)
	d, err := hex.DecodeString(dHex)
	if err != nil {
		t.Fatal(err)
	}
	z, err := hex.DecodeString(zHex)
	if err != nil {
		t.Fatal(err)
	}
	seed := append(append([]byte{}, d...), z...)

	kp, err := GenerateKyberKeyPairFromSeed(KyberLevel768, seed)
	if err != nil {
		t.Fatal(err)
	}
	got := sha256.Sum256(kp.PublicKey)
	if hex.EncodeToString(got[:]) != ekSHA256 {
		t.Errorf("ML-KEM-768: derived encapsulation key does not match NIST ACVP vector\n got  %x\n want %s",
			got, ekSHA256)
	}
}
