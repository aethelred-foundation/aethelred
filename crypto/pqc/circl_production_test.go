//go:build pqc_circl

package pqc

import (
	"bytes"
	"testing"
)

func TestCirclAvailableWithBuildTag(t *testing.T) {
	if !IsCirclAvailable() {
		t.Fatal("CIRCL backend reported unavailable with pqc_circl build tag")
	}
}

func TestTaggedMLDSARoundTripAllLevelsAndRequiredModes(t *testing.T) {
	previousMode := GetPQCMode()
	t.Cleanup(func() { SetPQCMode(previousMode) })

	for _, mode := range []PQCMode{PQCModeProduction, PQCModeHybrid} {
		t.Run(mode.String(), func(t *testing.T) {
			SetPQCMode(mode)

			for _, level := range []int{DilithiumLevel2, DilithiumLevel3, DilithiumLevel5} {
				t.Run(pqcLevelName(level), func(t *testing.T) {
					keyPair, err := GenerateCirclDilithiumKeyPair(level)
					if err != nil {
						t.Fatalf("key generation: %v", err)
					}
					if !keyPair.useCircl {
						t.Fatal("production/hybrid key pair did not select CIRCL")
					}

					params, err := GetDilithiumParams(level)
					if err != nil {
						t.Fatal(err)
					}
					if len(keyPair.PublicKey) != params.PublicKeySize {
						t.Fatalf("public key size = %d, want %d", len(keyPair.PublicKey), params.PublicKeySize)
					}
					if len(keyPair.PrivateKey) != params.PrivateKeySize {
						t.Fatalf("private key size = %d, want %d", len(keyPair.PrivateKey), params.PrivateKeySize)
					}

					message := []byte("aethelred CIRCL ML-DSA production round trip")
					signature, err := keyPair.Sign(message)
					if err != nil {
						t.Fatalf("sign: %v", err)
					}
					if len(signature.Signature) != params.SignatureSize {
						t.Fatalf("signature size = %d, want %d", len(signature.Signature), params.SignatureSize)
					}

					valid, err := VerifyCirclDilithium(keyPair.PublicKey, message, signature)
					if err != nil || !valid {
						t.Fatalf("verify: valid=%v err=%v", valid, err)
					}

					tamperedMessage := append([]byte(nil), message...)
					tamperedMessage[0] ^= 0xff
					if valid, err := VerifyCirclDilithium(keyPair.PublicKey, tamperedMessage, signature); err != nil || valid {
						t.Fatalf("tampered message: valid=%v err=%v", valid, err)
					}

					tamperedSignature := &DilithiumSignature{
						Level:     level,
						Signature: append([]byte(nil), signature.Signature...),
					}
					tamperedSignature.Signature[len(tamperedSignature.Signature)/2] ^= 0xff
					if valid, err := VerifyCirclDilithium(keyPair.PublicKey, message, tamperedSignature); err != nil || valid {
						t.Fatalf("tampered signature: valid=%v err=%v", valid, err)
					}
				})
			}
		})
	}
}

func TestTaggedMLKEMRoundTripAllLevelsAndRequiredModes(t *testing.T) {
	previousMode := GetPQCMode()
	t.Cleanup(func() { SetPQCMode(previousMode) })

	for _, mode := range []PQCMode{PQCModeProduction, PQCModeHybrid} {
		t.Run(mode.String(), func(t *testing.T) {
			SetPQCMode(mode)

			for _, level := range []int{KyberLevel512, KyberLevel768, KyberLevel1024} {
				t.Run(kyberLevelName(level), func(t *testing.T) {
					keyPair, err := GenerateCirclKyberKeyPair(level)
					if err != nil {
						t.Fatalf("key generation: %v", err)
					}
					if !keyPair.useCircl {
						t.Fatal("production/hybrid key pair did not select CIRCL")
					}

					params, err := GetKyberParams(level)
					if err != nil {
						t.Fatal(err)
					}
					if len(keyPair.PublicKey) != params.PublicKeySize {
						t.Fatalf("public key size = %d, want %d", len(keyPair.PublicKey), params.PublicKeySize)
					}
					if len(keyPair.PrivateKey) != params.PrivateKeySize {
						t.Fatalf("private key size = %d, want %d", len(keyPair.PrivateKey), params.PrivateKeySize)
					}

					sharedSecret, ciphertext, err := keyPair.Encapsulate(keyPair.PublicKey)
					if err != nil {
						t.Fatalf("encapsulate: %v", err)
					}
					if len(ciphertext.Ciphertext) != params.CiphertextSize {
						t.Fatalf("ciphertext size = %d, want %d", len(ciphertext.Ciphertext), params.CiphertextSize)
					}

					recoveredSecret, err := keyPair.Decapsulate(ciphertext)
					if err != nil {
						t.Fatalf("decapsulate: %v", err)
					}
					if !bytes.Equal(sharedSecret, recoveredSecret) {
						t.Fatal("encapsulated and decapsulated shared secrets differ")
					}

					tamperedCiphertext := &KyberCiphertext{
						Level:      level,
						Ciphertext: append([]byte(nil), ciphertext.Ciphertext...),
					}
					tamperedCiphertext.Ciphertext[len(tamperedCiphertext.Ciphertext)/2] ^= 0xff
					rejectedSecret, err := keyPair.Decapsulate(tamperedCiphertext)
					if err != nil {
						t.Fatalf("implicit rejection: %v", err)
					}
					if bytes.Equal(sharedSecret, rejectedSecret) {
						t.Fatal("tampered ciphertext recovered the original shared secret")
					}
				})
			}
		})
	}
}

func TestTaggedPublicAPIsUseRealBackendInRequiredModes(t *testing.T) {
	previousMode := GetPQCMode()
	t.Cleanup(func() { SetPQCMode(previousMode) })

	for _, mode := range []PQCMode{PQCModeProduction, PQCModeHybrid} {
		t.Run(mode.String(), func(t *testing.T) {
			SetPQCMode(mode)

			message := []byte("aethelred public PQC API routing")
			signingKey, err := GenerateDilithiumKeyPair(DilithiumLevel3)
			if err != nil {
				t.Fatalf("public ML-DSA key generation: %v", err)
			}
			firstSignature, err := signingKey.Sign(message)
			if err != nil {
				t.Fatalf("public ML-DSA signing: %v", err)
			}
			secondSignature, err := signingKey.Sign(message)
			if err != nil {
				t.Fatalf("second public ML-DSA signing: %v", err)
			}
			if bytes.Equal(firstSignature.Signature, secondSignature.Signature) {
				t.Fatal("production/hybrid ML-DSA signatures were deterministic; simulated backend may have been used")
			}
			if valid, err := VerifyDilithium(signingKey.PublicKey, message, firstSignature); err != nil || !valid {
				t.Fatalf("public ML-DSA verification: valid=%v err=%v", valid, err)
			}

			kemKey, err := GenerateKyberKeyPair(KyberLevel768)
			if err != nil {
				t.Fatalf("public ML-KEM key generation: %v", err)
			}
			sharedSecret, ciphertext, err := kemKey.Encapsulate()
			if err != nil {
				t.Fatalf("public ML-KEM encapsulation: %v", err)
			}
			recoveredSecret, err := kemKey.Decapsulate(ciphertext)
			if err != nil {
				t.Fatalf("public ML-KEM decapsulation: %v", err)
			}
			if !bytes.Equal(sharedSecret, recoveredSecret) {
				t.Fatal("public ML-KEM shared secrets differ")
			}
		})
	}
}

func pqcLevelName(level int) string {
	switch level {
	case DilithiumLevel2:
		return "ML-DSA-44"
	case DilithiumLevel3:
		return "ML-DSA-65"
	case DilithiumLevel5:
		return "ML-DSA-87"
	default:
		return "unknown"
	}
}

func kyberLevelName(level int) string {
	switch level {
	case KyberLevel512:
		return "ML-KEM-512"
	case KyberLevel768:
		return "ML-KEM-768"
	case KyberLevel1024:
		return "ML-KEM-1024"
	default:
		return "unknown"
	}
}
