//go:build !pqc_circl

package pqc

import (
	"strings"
	"testing"
)

func TestCirclUnavailableWithoutBuildTag(t *testing.T) {
	if IsCirclAvailable() {
		t.Fatal("CIRCL backend reported available without pqc_circl build tag")
	}
}

func TestProductionModesFailClosedWithoutCircl(t *testing.T) {
	previousMode := GetPQCMode()
	t.Cleanup(func() { SetPQCMode(previousMode) })

	SetPQCMode(PQCModeSimulated)
	simulatedDilithium, err := GenerateCirclDilithiumKeyPair(DilithiumLevel2)
	if err != nil {
		t.Fatalf("prepare simulated Dilithium key: %v", err)
	}
	simulatedKyber, err := GenerateCirclKyberKeyPair(KyberLevel512)
	if err != nil {
		t.Fatalf("prepare simulated Kyber key: %v", err)
	}

	for _, mode := range []PQCMode{PQCModeProduction, PQCModeHybrid} {
		t.Run(mode.String(), func(t *testing.T) {
			SetPQCMode(mode)

			assertCirclRequired(t, func() error {
				_, err := GenerateCirclDilithiumKeyPair(DilithiumLevel2)
				return err
			})
			assertCirclRequired(t, func() error {
				_, err := GenerateDilithiumKeyPair(DilithiumLevel2)
				return err
			})
			assertCirclRequired(t, func() error {
				_, err := simulatedDilithium.Sign([]byte("must not use simulated signing"))
				return err
			})
			assertCirclRequired(t, func() error {
				_, err := VerifyCirclDilithium(
					simulatedDilithium.PublicKey,
					[]byte("must not use simulated verification"),
					&DilithiumSignature{Level: DilithiumLevel2},
				)
				return err
			})

			assertCirclRequired(t, func() error {
				_, err := GenerateCirclKyberKeyPair(KyberLevel512)
				return err
			})
			assertCirclRequired(t, func() error {
				_, err := GenerateKyberKeyPair(KyberLevel512)
				return err
			})
			assertCirclRequired(t, func() error {
				_, _, err := simulatedKyber.Encapsulate(simulatedKyber.PublicKey)
				return err
			})
			assertCirclRequired(t, func() error {
				_, err := simulatedKyber.Decapsulate(&KyberCiphertext{Level: KyberLevel512})
				return err
			})
		})
	}
}

func assertCirclRequired(t *testing.T, operation func() error) {
	t.Helper()

	err := operation()
	if err == nil {
		t.Fatal("production/hybrid operation unexpectedly succeeded without CIRCL")
	}
	if !strings.Contains(err.Error(), "build with -tags=pqc_circl") {
		t.Fatalf("unexpected fail-closed error: %v", err)
	}
}
