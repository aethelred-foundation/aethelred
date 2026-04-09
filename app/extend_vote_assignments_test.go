package app

import (
	"bytes"
	"encoding/binary"
	"testing"

	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
	"github.com/aethelred/aethelred/x/verify/ezkl"
	"github.com/aethelred/aethelred/x/verify/tee"
	verifytypes "github.com/aethelred/aethelred/x/verify/types"
)

// ---------------------------------------------------------------------------
// mapProofType
// ---------------------------------------------------------------------------

func TestMapProofType_TEE(t *testing.T) {
	vt, err := mapProofType(pouwtypes.ProofTypeTEE)
	if err != nil {
		t.Fatal(err)
	}
	if vt != verifytypes.VerificationTypeTEE {
		t.Fatalf("expected VerificationTypeTEE, got %v", vt)
	}
}

func TestMapProofType_ZKML(t *testing.T) {
	vt, err := mapProofType(pouwtypes.ProofTypeZKML)
	if err != nil {
		t.Fatal(err)
	}
	if vt != verifytypes.VerificationTypeZKML {
		t.Fatalf("expected VerificationTypeZKML, got %v", vt)
	}
}

func TestMapProofType_Hybrid(t *testing.T) {
	vt, err := mapProofType(pouwtypes.ProofTypeHybrid)
	if err != nil {
		t.Fatal(err)
	}
	if vt != verifytypes.VerificationTypeHybrid {
		t.Fatalf("expected VerificationTypeHybrid, got %v", vt)
	}
}

func TestMapProofType_Unknown(t *testing.T) {
	_, err := mapProofType(pouwtypes.ProofType(99))
	if err == nil {
		t.Fatal("expected error for unknown proof type")
	}
}

func TestMapProofType_Unspecified(t *testing.T) {
	_, err := mapProofType(pouwtypes.ProofType_PROOF_TYPE_UNSPECIFIED)
	if err == nil {
		t.Fatal("expected error for unspecified proof type")
	}
}

// ---------------------------------------------------------------------------
// nitroMeasurement
// ---------------------------------------------------------------------------

func TestNitroMeasurement_NilDoc(t *testing.T) {
	result := nitroMeasurement(nil)
	if result != nil {
		t.Fatal("expected nil for nil doc")
	}
}

func TestNitroMeasurement_NilPCRs(t *testing.T) {
	doc := &tee.NitroAttestationDocument{PCRs: nil}
	result := nitroMeasurement(doc)
	if result != nil {
		t.Fatal("expected nil for nil PCRs")
	}
}

func TestNitroMeasurement_WithPCR0(t *testing.T) {
	pcr0 := []byte("pcr0-measurement-value")
	doc := &tee.NitroAttestationDocument{
		PCRs: map[int][]byte{0: pcr0},
	}
	result := nitroMeasurement(doc)
	if !bytes.Equal(result, pcr0) {
		t.Fatal("expected PCR0 value")
	}
}

func TestNitroMeasurement_MultiplePCRsCombined(t *testing.T) {
	doc := &tee.NitroAttestationDocument{
		PCRs: map[int][]byte{
			0: {},
			1: []byte("pcr1"),
			2: []byte("pcr2"),
		},
	}
	result := nitroMeasurement(doc)
	// PCR0 is empty, so it falls through to combine all PCRs.
	if len(result) == 0 {
		t.Fatal("expected combined PCR values")
	}
}

// ---------------------------------------------------------------------------
// marshalNitroQuote
// ---------------------------------------------------------------------------

func TestMarshalNitroQuote_NilDoc(t *testing.T) {
	result := marshalNitroQuote(nil)
	if result != nil {
		t.Fatal("expected nil for nil doc")
	}
}

func TestMarshalNitroQuote_ValidDoc(t *testing.T) {
	doc := &tee.NitroAttestationDocument{
		ModuleID: "test-module",
		PCRs:     map[int][]byte{0: []byte("pcr0")},
	}
	result := marshalNitroQuote(doc)
	if len(result) == 0 {
		t.Fatal("expected non-empty quote bytes")
	}
}

// ---------------------------------------------------------------------------
// marshalZKPublicInputs
// ---------------------------------------------------------------------------

func TestMarshalZKPublicInputs_Nil(t *testing.T) {
	result := marshalZKPublicInputs(nil)
	if result != nil {
		t.Fatal("expected nil for nil inputs")
	}
}

func TestMarshalZKPublicInputs_Valid(t *testing.T) {
	inputs := &ezkl.PublicInputs{
		ModelCommitment:  []byte("model"),
		InputCommitment:  []byte("input"),
		OutputCommitment: []byte("output"),
		Instances:        [][]byte{[]byte("inst1"), []byte("inst2")},
	}
	result := marshalZKPublicInputs(inputs)
	if len(result) == 0 {
		t.Fatal("expected non-empty serialized public inputs")
	}
}

func TestMarshalZKPublicInputs_EmptyFields(t *testing.T) {
	inputs := &ezkl.PublicInputs{}
	result := marshalZKPublicInputs(inputs)
	// Should still produce output (length-prefixed empty fields).
	if result == nil {
		t.Fatal("expected non-nil result even with empty fields")
	}
}

// ---------------------------------------------------------------------------
// writeLenPrefixed
// ---------------------------------------------------------------------------

func TestWriteLenPrefixed_EmptyData(t *testing.T) {
	var buf bytes.Buffer
	writeLenPrefixed(&buf, nil)
	// Should write a 4-byte zero length prefix.
	if buf.Len() != 4 {
		t.Fatalf("expected 4 bytes for nil data, got %d", buf.Len())
	}
	length := binary.BigEndian.Uint32(buf.Bytes())
	if length != 0 {
		t.Fatalf("expected zero length, got %d", length)
	}
}

func TestWriteLenPrefixed_NonEmptyData(t *testing.T) {
	var buf bytes.Buffer
	data := []byte("hello")
	writeLenPrefixed(&buf, data)
	// 4 bytes length + 5 bytes data.
	if buf.Len() != 9 {
		t.Fatalf("expected 9 bytes, got %d", buf.Len())
	}
	length := binary.BigEndian.Uint32(buf.Bytes()[:4])
	if length != 5 {
		t.Fatalf("expected length 5, got %d", length)
	}
	if !bytes.Equal(buf.Bytes()[4:], data) {
		t.Fatal("data mismatch")
	}
}

// ---------------------------------------------------------------------------
// mapTEEAttestation
// ---------------------------------------------------------------------------

func TestMapTEEAttestation_NilResult(t *testing.T) {
	result := mapTEEAttestation(nil)
	if result != nil {
		t.Fatal("expected nil for nil TEE result")
	}
}

// ---------------------------------------------------------------------------
// mapZKProof
// ---------------------------------------------------------------------------

func TestMapZKProof_NilResult(t *testing.T) {
	result := mapZKProof(nil, nil)
	if result != nil {
		t.Fatal("expected nil for nil ZK result")
	}
}
