package tee

import (
	"context"
	"testing"
	"time"

	"cosmossdk.io/log"
)

func TestVerifySimulatedNitroAttestationRejectsTampering(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	doc := &NitroAttestationDocument{
		ModuleID:  "nitro-simulated",
		Timestamp: time.Now().UTC(),
		Digest:    "SHA384",
		PCRs: map[int][]byte{
			0: []byte("pcr0"),
			1: []byte("pcr1"),
		},
		UserData: []byte("output-hash"),
		Nonce:    []byte("nonce"),
	}
	doc.Signature = SignSimulatedNitroAttestation(doc, key)

	if err := VerifySimulatedNitroAttestation(doc, key); err != nil {
		t.Fatalf("expected valid simulated attestation, got %v", err)
	}

	doc.UserData = []byte("tampered")
	if err := VerifySimulatedNitroAttestation(doc, key); err == nil {
		t.Fatalf("expected tampered simulated attestation to fail verification")
	}
}

func TestNitroServiceVerifyAttestationRejectsUnsignedSimulation(t *testing.T) {
	service := NewNitroEnclaveService(log.NewNopLogger(), NitroConfig{
		AllowSimulated:            true,
		AttestationDocumentMaxAge: 5 * time.Minute,
		SimulatedAttestationKey:   []byte("0123456789abcdef0123456789abcdef"),
	})

	doc := &NitroAttestationDocument{
		ModuleID:  "nitro-simulated",
		Timestamp: time.Now().UTC(),
		Digest:    "SHA384",
		PCRs: map[int][]byte{
			0: []byte("pcr0"),
		},
		UserData: []byte("output-hash"),
		Nonce:    []byte("nonce"),
	}

	result, err := service.VerifyAttestation(context.Background(), doc)
	if err != nil {
		t.Fatalf("expected simulated verification result, got error %v", err)
	}
	if result.Valid {
		t.Fatalf("expected unsigned simulated attestation to be rejected")
	}
}
