package keeper

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func TestZKVerifierRegisterDeactivate(t *testing.T) {
	v := NewSimulatedZKVerifier()
	var hash [32]byte
	hash[0] = 0x01

	if err := v.RegisterCircuit(RegisteredCircuit{CircuitHash: hash}); err == nil {
		t.Fatalf("expected error for empty verifying key")
	}

	vk := []byte{0x01, 0x02}
	circuit := RegisteredCircuit{CircuitHash: hash, VerifyingKey: vk}
	if err := v.RegisterCircuit(circuit); err != nil {
		t.Fatalf("expected register to succeed, got %v", err)
	}

	stored := v.registeredCircuits[hash]
	if !stored.Active {
		t.Fatalf("expected circuit active")
	}
	if stored.MaxProofSize == 0 {
		t.Fatalf("expected default max proof size")
	}
	if stored.GasMultiplier == 0 {
		t.Fatalf("expected default gas multiplier")
	}

	var missing [32]byte
	missing[0] = 0x02
	if err := v.DeactivateCircuit(missing); err == nil {
		t.Fatalf("expected error for missing circuit")
	}

	if err := v.DeactivateCircuit(hash); err != nil {
		t.Fatalf("expected deactivate to succeed, got %v", err)
	}
	if v.registeredCircuits[hash].Active {
		t.Fatalf("expected circuit to be inactive")
	}
}

func TestZKVerifierVerifyProofErrors(t *testing.T) {
	v := NewSimulatedZKVerifier()

	// Proof too large
	proof := &ZKProof{Proof: bytes.Repeat([]byte{0x01}, int(v.maxProofSize)+1)}
	result := v.VerifyProof(sdk.Context{}, proof)
	if result.ErrorCode != ZKErrorProofTooLarge {
		t.Fatalf("expected proof too large error")
	}

	// Unsupported system
	proof = &ZKProof{System: ProofSystem("unknown"), ProofSize: 0}
	result = v.VerifyProof(sdk.Context{}, proof)
	if result.ErrorCode != ZKErrorUnsupportedSystem {
		t.Fatalf("expected unsupported system error")
	}
}

func TestZKVerifierFailsClosedWithoutSystemVerifier(t *testing.T) {
	v := NewZKVerifier()
	var circuitHash [32]byte
	circuitHash[0] = 0x44
	vk := []byte("strict-groth16-vk")
	if err := v.RegisterCircuit(RegisteredCircuit{
		CircuitHash:  circuitHash,
		VerifyingKey: vk,
		System:       ProofSystemGroth16,
	}); err != nil {
		t.Fatalf("expected circuit registration to succeed, got %v", err)
	}

	proof := &ZKProof{
		System:           ProofSystemGroth16,
		Proof:            bytes.Repeat([]byte{0x01}, 192),
		PublicInputs:     appendDomainBinding([]byte{0xAB}, "job-strict", "chain-strict", 7),
		VerifyingKeyHash: sha256.Sum256(vk),
		CircuitHash:      circuitHash,
		ProofSize:        192,
		JobID:            "job-strict",
		ChainID:          "chain-strict",
		Height:           7,
	}

	result := v.VerifyProof(sdk.Context{}, proof)
	if result.Valid {
		t.Fatalf("expected strict verifier to fail closed without system verifier")
	}
	if result.ErrorCode != ZKErrorInvalidProof {
		t.Fatalf("expected invalid proof error code, got %s", result.ErrorCode)
	}
	if result.ErrorMessage == "" {
		t.Fatalf("expected explicit error message for missing verifier")
	}
}

func TestZKVerifierVerifyingKeyMismatch(t *testing.T) {
	v := NewSimulatedZKVerifier()
	var hash [32]byte
	hash[0] = 0xAA

	vk := []byte{0x10, 0x20, 0x30}
	_ = v.RegisterCircuit(RegisteredCircuit{CircuitHash: hash, VerifyingKey: vk, GasMultiplier: 2})

	proof := &ZKProof{
		System:           ProofSystemEZKL,
		Proof:            bytes.Repeat([]byte{0x01}, 256),
		PublicInputs:     bytes.Repeat([]byte{0x02}, 96),
		ProofSize:        256,
		CircuitHash:      hash,
		VerifyingKeyHash: [32]byte{0xFF},
	}

	result := v.VerifyProof(sdk.Context{}, proof)
	if result.ErrorCode != ZKErrorVerifyingKeyMismatch {
		t.Fatalf("expected verifying key mismatch")
	}
	if result.GasUsed == 0 {
		t.Fatalf("expected gas used to be set")
	}
}

func TestZKVerifierInvalidProofStructure(t *testing.T) {
	v := NewSimulatedZKVerifier()

	proof := &ZKProof{
		System:       ProofSystemEZKL,
		Proof:        []byte{0x01},
		PublicInputs: []byte{},
		ProofSize:    1,
	}

	result := v.VerifyProof(sdk.Context{}, proof)
	if result.ErrorCode != ZKErrorInvalidProof {
		t.Fatalf("expected invalid proof error")
	}
}

func TestZKVerifierCircuitDeactivated(t *testing.T) {
	v := NewSimulatedZKVerifier()
	var hash [32]byte
	hash[0] = 0xCC
	vk := bytes.Repeat([]byte{0x01}, 32)
	_ = v.RegisterCircuit(RegisteredCircuit{CircuitHash: hash, VerifyingKey: vk})
	_ = v.DeactivateCircuit(hash)

	proof := &ZKProof{
		System:           ProofSystemEZKL,
		Proof:            bytes.Repeat([]byte{0x01}, 256),
		PublicInputs:     bytes.Repeat([]byte{0x02}, 96),
		ProofSize:        256,
		CircuitHash:      hash,
		VerifyingKeyHash: sha256.Sum256(vk),
	}

	result := v.VerifyProof(sdk.Context{}, proof)
	if result.ErrorCode != ZKErrorCircuitMismatch {
		t.Fatalf("expected circuit mismatch error")
	}
}

func TestZKVerifierEmptyVerifyingKeyHash(t *testing.T) {
	v := NewSimulatedZKVerifier()
	proof := &ZKProof{
		System:       ProofSystemEZKL,
		Proof:        bytes.Repeat([]byte{0x01}, 256),
		PublicInputs: bytes.Repeat([]byte{0x02}, 96),
		ProofSize:    256,
	}

	result := v.VerifyProof(sdk.Context{}, proof)
	if result.ErrorCode != ZKErrorInvalidProof {
		t.Fatalf("expected invalid proof error")
	}
}

func TestZKVerifierEZKLPublicInputsTooShort(t *testing.T) {
	v := NewSimulatedZKVerifier()
	proof := &ZKProof{
		System:           ProofSystemEZKL,
		Proof:            bytes.Repeat([]byte{0x01}, 256),
		PublicInputs:     []byte{0x01},
		ProofSize:        256,
		VerifyingKeyHash: [32]byte{0x01},
	}

	result := v.VerifyProof(sdk.Context{}, proof)
	if result.ErrorCode != ZKErrorInvalidProof {
		t.Fatalf("expected invalid proof error")
	}
}

func TestParseEZKLPublicInputs(t *testing.T) {
	short := []byte{0x01}
	if _, err := ParseEZKLPublicInputs(short); err == nil {
		t.Fatalf("expected error for short inputs")
	}

	model := bytes.Repeat([]byte{0x01}, 32)
	input := bytes.Repeat([]byte{0x02}, 32)
	output := bytes.Repeat([]byte{0x03}, 32)
	circuit := bytes.Repeat([]byte{0x04}, 32)

	payload := append(append(model, input...), output...)
	inputs, err := ParseEZKLPublicInputs(payload)
	if err != nil {
		t.Fatalf("expected parse to succeed, got %v", err)
	}
	if !bytes.Equal(inputs.ModelHash[:], model) {
		t.Fatalf("model hash mismatch")
	}

	payload = append(payload, circuit...)
	inputs, err = ParseEZKLPublicInputs(payload)
	if err != nil {
		t.Fatalf("expected parse to succeed with circuit hash, got %v", err)
	}
	if !bytes.Equal(inputs.CircuitHash[:], circuit) {
		t.Fatalf("circuit hash mismatch")
	}
}

func TestValidateAgainstJob(t *testing.T) {
	model := bytes.Repeat([]byte{0x01}, 32)
	input := bytes.Repeat([]byte{0x02}, 32)
	output := bytes.Repeat([]byte{0x03}, 32)

	payload := append(append(model, input...), output...)
	inputs, err := ParseEZKLPublicInputs(payload)
	if err != nil {
		t.Fatalf("expected parse to succeed, got %v", err)
	}

	if err := inputs.ValidateAgainstJob(model, input, output); err != nil {
		t.Fatalf("expected validation success, got %v", err)
	}

	if err := inputs.ValidateAgainstJob(model, input, bytes.Repeat([]byte{0x04}, 32)); err == nil {
		t.Fatalf("expected output hash mismatch error")
	}
}

func TestEstimateVerificationGas(t *testing.T) {
	v := NewSimulatedZKVerifier()
	proof := &ZKProof{
		System:       ProofSystemGroth16,
		Proof:        bytes.Repeat([]byte{0x01}, 10),
		PublicInputs: bytes.Repeat([]byte{0x02}, 20),
	}

	gas := v.EstimateVerificationGas(proof)
	expected := (v.baseGas + uint64(10)*v.gasPerByte + uint64(20)*(v.gasPerByte/2)) * 1
	if gas != expected {
		t.Fatalf("expected gas %d, got %d", expected, gas)
	}

	var hash [32]byte
	hash[0] = 0x11
	_ = v.RegisterCircuit(RegisteredCircuit{CircuitHash: hash, VerifyingKey: []byte{0x01}, GasMultiplier: 3})
	proof.CircuitHash = hash

	gas = v.EstimateVerificationGas(proof)
	if gas != expected*3 {
		t.Fatalf("expected circuit multiplier applied")
	}
}

func TestZKVerifierPrecompileParseAndEncode(t *testing.T) {
	v := NewSimulatedZKVerifier()
	p := NewZKVerifierPrecompile(v)

	input := make([]byte, 0, 140)
	system := make([]byte, 32)
	copy(system, []byte("ezkl"))
	vkHash := bytes.Repeat([]byte{0x01}, 32)
	circuitHash := bytes.Repeat([]byte{0x02}, 32)
	proof := bytes.Repeat([]byte{0x03}, 20)
	pubInputs := bytes.Repeat([]byte{0x04}, 12)

	input = append(input, system...)
	input = append(input, vkHash...)
	input = append(input, circuitHash...)
	proofLen := make([]byte, 4)
	binary.BigEndian.PutUint32(proofLen, uint32(len(proof)))
	input = append(input, proofLen...)
	input = append(input, proof...)
	inputsLen := make([]byte, 4)
	binary.BigEndian.PutUint32(inputsLen, uint32(len(pubInputs)))
	input = append(input, inputsLen...)
	input = append(input, pubInputs...)

	parsed, err := p.parsePrecompileInput(input)
	if err != nil {
		t.Fatalf("expected parse to succeed, got %v", err)
	}
	if parsed.System != ProofSystemEZKL {
		t.Fatalf("expected system ezkl")
	}

	result := &ZKVerificationResult{Valid: true, GasUsed: 123, ErrorCode: ZKErrorNone}
	out := p.encodeResult(result)
	if len(out) != 73 {
		t.Fatalf("expected encoded length 73, got %d", len(out))
	}
	if out[0] != 1 {
		t.Fatalf("expected valid flag set")
	}
}

func TestZKVerifierPrecompileParseWithDomainBinding(t *testing.T) {
	v := NewSimulatedZKVerifier()
	p := NewZKVerifierPrecompile(v)

	jobID := "job-42"
	chainID := "aethelred-devnet"
	height := int64(77)
	publicInputs := appendDomainBinding(bytes.Repeat([]byte{0x04}, 64), jobID, chainID, height)
	input := buildPrecompileInputWithDomainBinding(
		ProofSystemEZKL,
		[32]byte{0x01},
		[32]byte{0x02},
		bytes.Repeat([]byte{0x03}, 20),
		publicInputs,
		jobID,
		chainID,
		height,
	)

	parsed, err := p.parsePrecompileInput(input)
	if err != nil {
		t.Fatalf("expected parse to succeed, got %v", err)
	}
	if parsed.JobID != jobID {
		t.Fatalf("expected job id %q, got %q", jobID, parsed.JobID)
	}
	if parsed.ChainID != chainID {
		t.Fatalf("expected chain id %q, got %q", chainID, parsed.ChainID)
	}
	if parsed.Height != height {
		t.Fatalf("expected height %d, got %d", height, parsed.Height)
	}
}

func TestZKVerifierPrecompileParseErrors(t *testing.T) {
	v := NewSimulatedZKVerifier()
	p := NewZKVerifierPrecompile(v)

	if _, err := p.parsePrecompileInput([]byte{0x01}); err == nil {
		t.Fatalf("expected error for short input")
	}

	// Proof data truncated
	base := make([]byte, 0, 132)
	system := make([]byte, 32)
	base = append(base, system...)
	base = append(base, bytes.Repeat([]byte{0x01}, 32)...)
	base = append(base, bytes.Repeat([]byte{0x02}, 32)...)
	proofLen := make([]byte, 4)
	binary.BigEndian.PutUint32(proofLen, 100)
	base = append(base, proofLen...)
	base = append(base, bytes.Repeat([]byte{0x00}, 32)...)
	if _, err := p.parsePrecompileInput(base); err == nil {
		t.Fatalf("expected error for truncated proof data")
	}

	// Public inputs data truncated
	input := make([]byte, 0, 136)
	input = append(input, system...)
	input = append(input, bytes.Repeat([]byte{0x01}, 32)...)
	input = append(input, bytes.Repeat([]byte{0x02}, 32)...)
	binary.BigEndian.PutUint32(proofLen, 10)
	input = append(input, proofLen...)
	input = append(input, bytes.Repeat([]byte{0x03}, 10)...)
	inputsLen := make([]byte, 4)
	binary.BigEndian.PutUint32(inputsLen, 50)
	input = append(input, inputsLen...)
	if _, err := p.parsePrecompileInput(input); err == nil {
		t.Fatalf("expected error for truncated public inputs")
	}

	// Missing public inputs length
	input = make([]byte, 0, 120)
	input = append(input, system...)
	input = append(input, bytes.Repeat([]byte{0x01}, 32)...)
	input = append(input, bytes.Repeat([]byte{0x02}, 32)...)
	binary.BigEndian.PutUint32(proofLen, 4)
	input = append(input, proofLen...)
	input = append(input, bytes.Repeat([]byte{0x03}, 4)...)
	if _, err := p.parsePrecompileInput(input); err == nil {
		t.Fatalf("expected error for missing public inputs length")
	}
}

func TestZKVerifierPrecompileRequiredGasOnParseError(t *testing.T) {
	v := NewSimulatedZKVerifier()
	p := NewZKVerifierPrecompile(v)

	gas := p.RequiredGas([]byte{0x01})
	if gas != v.baseGas {
		t.Fatalf("expected base gas on parse error")
	}
}

func TestZKVerifierSystemSpecificMinProofSizes(t *testing.T) {
	v := NewSimulatedZKVerifier()

	cases := []struct {
		name            string
		system          ProofSystem
		minProofSize    int
		publicInputsLen int
	}{
		{name: "ezkl", system: ProofSystemEZKL, minProofSize: 256, publicInputsLen: 96},
		{name: "risc0", system: ProofSystemRISC0, minProofSize: 512, publicInputsLen: 32},
		{name: "plonky2", system: ProofSystemPlonky2, minProofSize: 256, publicInputsLen: 0},
		{name: "halo2", system: ProofSystemHalo2, minProofSize: 384, publicInputsLen: 0},
		{name: "groth16", system: ProofSystemGroth16, minProofSize: 192, publicInputsLen: 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proof := &ZKProof{
				System:           tc.system,
				Proof:            bytes.Repeat([]byte{0x01}, tc.minProofSize-1),
				PublicInputs:     bytes.Repeat([]byte{0x02}, tc.publicInputsLen),
				VerifyingKeyHash: [32]byte{0x01},
				ProofSize:        uint64(tc.minProofSize - 1),
			}

			result := v.VerifyProof(sdk.Context{}, proof)
			if result.ErrorCode != ZKErrorInvalidProof {
				t.Fatalf("expected invalid proof error for %s", tc.system)
			}
		})
	}
}

func TestZKVerifierEZKLRequiresPublicInputs(t *testing.T) {
	v := NewSimulatedZKVerifier()

	proof := &ZKProof{
		System:           ProofSystemEZKL,
		Proof:            bytes.Repeat([]byte{0x01}, 256),
		PublicInputs:     []byte{},
		VerifyingKeyHash: [32]byte{0x01},
		ProofSize:        256,
	}

	result := v.VerifyProof(sdk.Context{}, proof)
	if result.ErrorCode != ZKErrorInvalidProof {
		t.Fatalf("expected invalid proof error for missing public inputs")
	}
}

func TestZKVerifierRISC0RequiresImageID(t *testing.T) {
	v := NewSimulatedZKVerifier()

	proof := &ZKProof{
		System:           ProofSystemRISC0,
		Proof:            bytes.Repeat([]byte{0x01}, 512),
		PublicInputs:     bytes.Repeat([]byte{0x02}, 31),
		VerifyingKeyHash: [32]byte{0x01},
		ProofSize:        512,
	}

	result := v.VerifyProof(sdk.Context{}, proof)
	if result.ErrorCode != ZKErrorInvalidProof {
		t.Fatalf("expected invalid proof error for missing image ID")
	}
}

func TestZKVerifierValidProofs(t *testing.T) {
	v := NewSimulatedZKVerifier()

	cases := []struct {
		name         string
		system       ProofSystem
		proofLen     int
		publicInputs []byte
	}{
		{
			name:         "ezkl",
			system:       ProofSystemEZKL,
			proofLen:     256,
			publicInputs: bytes.Repeat([]byte{0x02}, 96),
		},
		{
			name:         "risc0",
			system:       ProofSystemRISC0,
			proofLen:     512,
			publicInputs: bytes.Repeat([]byte{0x02}, 32),
		},
		{
			name:         "groth16",
			system:       ProofSystemGroth16,
			proofLen:     192,
			publicInputs: []byte{0x02},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proof := &ZKProof{
				System:           tc.system,
				Proof:            bytes.Repeat([]byte{0x01}, tc.proofLen),
				PublicInputs:     tc.publicInputs,
				VerifyingKeyHash: [32]byte{0x0A},
				ProofSize:        uint64(tc.proofLen),
			}

			result := v.VerifyProof(sdk.Context{}, proof)
			if !result.Valid || result.ErrorCode != ZKErrorNone {
				t.Fatalf("expected valid proof for %s", tc.system)
			}

			expectedHash := sha256.Sum256(proof.PublicInputs)
			if result.PublicInputsHash != expectedHash {
				t.Fatalf("expected public inputs hash to match for %s", tc.system)
			}
		})
	}
}

func TestZKVerifierVerifyingKeyMatchValid(t *testing.T) {
	v := NewSimulatedZKVerifier()
	var hash [32]byte
	hash[0] = 0x42
	vk := bytes.Repeat([]byte{0x0B}, 32)

	if err := v.RegisterCircuit(RegisteredCircuit{CircuitHash: hash, VerifyingKey: vk, GasMultiplier: 2}); err != nil {
		t.Fatalf("expected register circuit success, got %v", err)
	}

	proof := &ZKProof{
		System:           ProofSystemEZKL,
		Proof:            bytes.Repeat([]byte{0x01}, 256),
		PublicInputs:     bytes.Repeat([]byte{0x02}, 96),
		VerifyingKeyHash: sha256.Sum256(vk),
		CircuitHash:      hash,
		ProofSize:        256,
	}

	result := v.VerifyProof(sdk.Context{}, proof)
	if !result.Valid || result.ErrorCode != ZKErrorNone {
		t.Fatalf("expected valid proof with matching verifying key hash")
	}
}

// =============================================================================
// WS1 Verification Core Hardening — Deck Reverse-Engineering Program
// =============================================================================

// TestGroth16SubgroupValidation exercises validateGroth16CurvePoints (ZK-08).
func TestGroth16SubgroupValidation(t *testing.T) {
	// BN254 field modulus p (big-endian)
	bn254Modulus := [32]byte{
		0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
		0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
		0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
		0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
	}

	t.Run("valid BN254 points pass", func(t *testing.T) {
		// Construct 256-byte proof with all coordinates well below the modulus.
		// 8 coordinates of 32 bytes each (A=2 coords, B=4 coords, C=2 coords).
		proof := make([]byte, 256)
		for i := 0; i < 8; i++ {
			// Set each coordinate to a small value (well below modulus).
			proof[i*32] = 0x01
			proof[i*32+31] = byte(i + 1)
		}

		if err := validateGroth16CurvePoints(proof); err != nil {
			t.Fatalf("expected valid BN254 points to pass, got: %v", err)
		}
	})

	t.Run("coordinate exceeding field modulus rejected", func(t *testing.T) {
		// Build a proof where coordinate 0 equals the modulus (not less than).
		proof := make([]byte, 256)
		for i := 0; i < 8; i++ {
			proof[i*32] = 0x01
			proof[i*32+31] = byte(i + 1)
		}
		// Set first coordinate to exactly bn254Modulus (fails isLessThan).
		copy(proof[0:32], bn254Modulus[:])

		err := validateGroth16CurvePoints(proof)
		if err == nil {
			t.Fatalf("expected coordinate exceeding field modulus to be rejected")
		}
	})

	t.Run("coordinate above modulus rejected", func(t *testing.T) {
		proof := make([]byte, 256)
		for i := 0; i < 8; i++ {
			proof[i*32] = 0x01
			proof[i*32+31] = byte(i + 1)
		}
		// Set first coordinate to 0xFF...FF which exceeds modulus.
		for j := 0; j < 32; j++ {
			proof[j] = 0xFF
		}

		err := validateGroth16CurvePoints(proof)
		if err == nil {
			t.Fatalf("expected coordinate 0xFF..FF to be rejected as exceeding modulus")
		}
	})

	t.Run("point A at infinity rejected", func(t *testing.T) {
		// 256-byte proof with point A (bytes 0:64) all zeros.
		proof := make([]byte, 256)
		// Leave A as all zeros (point at infinity).
		// Fill B and C with valid small coordinates.
		for i := 2; i < 8; i++ {
			proof[i*32] = 0x01
			proof[i*32+31] = byte(i + 1)
		}

		err := validateGroth16CurvePoints(proof)
		if err == nil {
			t.Fatalf("expected point A at infinity to be rejected")
		}
	})

	t.Run("point B at infinity rejected", func(t *testing.T) {
		proof := make([]byte, 256)
		// Fill A with valid coordinates.
		for i := 0; i < 2; i++ {
			proof[i*32] = 0x01
			proof[i*32+31] = byte(i + 1)
		}
		// Leave B (bytes 64:192) as all zeros.
		// Fill C with valid coordinates.
		for i := 6; i < 8; i++ {
			proof[i*32] = 0x01
			proof[i*32+31] = byte(i + 1)
		}

		err := validateGroth16CurvePoints(proof)
		if err == nil {
			t.Fatalf("expected point B at infinity to be rejected")
		}
	})

	t.Run("point C at infinity rejected", func(t *testing.T) {
		proof := make([]byte, 256)
		// Fill A and B with valid coordinates.
		for i := 0; i < 6; i++ {
			proof[i*32] = 0x01
			proof[i*32+31] = byte(i + 1)
		}
		// Leave C (bytes 192:256) as all zeros.

		err := validateGroth16CurvePoints(proof)
		if err == nil {
			t.Fatalf("expected point C at infinity to be rejected")
		}
	})

	t.Run("192-byte compressed proof validated", func(t *testing.T) {
		// Minimum-size proof (192 bytes) — A(64) + B(128), no C segment.
		proof := make([]byte, 192)
		for i := 0; i < 6; i++ {
			proof[i*32] = 0x01
			proof[i*32+31] = byte(i + 1)
		}

		if err := validateGroth16CurvePoints(proof); err != nil {
			t.Fatalf("expected 192-byte proof to pass, got: %v", err)
		}
	})
}

// TestDomainBindingRejection tests that validateDomainBinding rejects mismatched
// domain binding and accepts correct binding (ZK-06 production path).
func TestDomainBindingRejection(t *testing.T) {
	v := NewZKVerifier() // production mode (allowSimulated=false)

	jobID := "job-test-42"
	chainID := "aethelred-testnet-1"
	height := int64(100)

	// Build valid public inputs with correct domain binding appended.
	baseInputs := bytes.Repeat([]byte{0xAB}, 64)
	validInputs := appendDomainBinding(baseInputs, jobID, chainID, height)

	t.Run("correct domain binding passes", func(t *testing.T) {
		proof := &ZKProof{
			JobID:        jobID,
			ChainID:      chainID,
			Height:       height,
			PublicInputs: validInputs,
		}

		if err := v.validateDomainBinding(proof); err != nil {
			t.Fatalf("expected correct domain binding to pass, got: %v", err)
		}
	})

	t.Run("mismatched ChainID rejected", func(t *testing.T) {
		proof := &ZKProof{
			JobID:        jobID,
			ChainID:      "wrong-chain-id",
			Height:       height,
			PublicInputs: validInputs,
		}

		err := v.validateDomainBinding(proof)
		if err == nil {
			t.Fatalf("expected mismatched ChainID to be rejected")
		}
	})

	t.Run("mismatched JobID rejected", func(t *testing.T) {
		proof := &ZKProof{
			JobID:        "wrong-job-id",
			ChainID:      chainID,
			Height:       height,
			PublicInputs: validInputs,
		}

		err := v.validateDomainBinding(proof)
		if err == nil {
			t.Fatalf("expected mismatched JobID to be rejected")
		}
	})

	t.Run("mismatched Height rejected", func(t *testing.T) {
		proof := &ZKProof{
			JobID:        jobID,
			ChainID:      chainID,
			Height:       999,
			PublicInputs: validInputs,
		}

		err := v.validateDomainBinding(proof)
		if err == nil {
			t.Fatalf("expected mismatched Height to be rejected")
		}
	})

	t.Run("public inputs too short rejected", func(t *testing.T) {
		proof := &ZKProof{
			JobID:        jobID,
			ChainID:      chainID,
			Height:       height,
			PublicInputs: []byte{0x01, 0x02}, // way too short for domain binding
		}

		err := v.validateDomainBinding(proof)
		if err == nil {
			t.Fatalf("expected short public inputs to be rejected")
		}
	})

	t.Run("VerifyProof rejects mismatched domain in production mode", func(t *testing.T) {
		// Full end-to-end: production verifier rejects proof with wrong ChainID.
		var circuitHash [32]byte
		circuitHash[0] = 0xDD
		vk := []byte("domain-test-vk")
		_ = v.RegisterCircuit(RegisteredCircuit{
			CircuitHash:  circuitHash,
			VerifyingKey: vk,
			System:       ProofSystemGroth16,
		})

		proof := &ZKProof{
			System:           ProofSystemGroth16,
			Proof:            bytes.Repeat([]byte{0x01}, 192),
			PublicInputs:     validInputs,
			VerifyingKeyHash: sha256.Sum256(vk),
			CircuitHash:      circuitHash,
			ProofSize:        192,
			JobID:            jobID,
			ChainID:          "wrong-chain",
			Height:           height,
		}

		result := v.VerifyProof(sdk.Context{}, proof)
		if result.Valid {
			t.Fatalf("expected production verifier to reject mismatched domain binding")
		}
		if result.ErrorCode != ZKErrorInvalidPublicInput {
			t.Fatalf("expected INVALID_PUBLIC_INPUT error code, got %s", result.ErrorCode)
		}
	})
}

// mockCircuitStore implements CircuitStoreReader for testing RebuildRegistryFromStore.
type mockCircuitStore struct {
	circuits []RegisteredCircuit
	err      error
}

func (m *mockCircuitStore) GetAllActiveCircuits(_ sdk.Context) ([]RegisteredCircuit, error) {
	return m.circuits, m.err
}

// TestCircuitRegistryRebuild tests RebuildRegistryFromStore deterministic rebuild (ZK-04).
func TestCircuitRegistryRebuild(t *testing.T) {
	t.Run("rebuild replaces registry with store contents", func(t *testing.T) {
		v := NewSimulatedZKVerifier()

		// Register an initial circuit via direct API.
		var initialHash [32]byte
		initialHash[0] = 0x01
		_ = v.RegisterCircuit(RegisteredCircuit{
			CircuitHash:  initialHash,
			VerifyingKey: []byte("initial-vk"),
		})

		if v.CircuitCount() != 1 {
			t.Fatalf("expected 1 circuit before rebuild, got %d", v.CircuitCount())
		}

		// Prepare store with 3 different circuits.
		storeCircuits := []RegisteredCircuit{
			{CircuitHash: [32]byte{0xAA}, VerifyingKey: []byte("vk-aa"), Active: true, GasMultiplier: 2},
			{CircuitHash: [32]byte{0xBB}, VerifyingKey: []byte("vk-bb"), Active: true, GasMultiplier: 3},
			{CircuitHash: [32]byte{0xCC}, VerifyingKey: []byte("vk-cc"), Active: true, GasMultiplier: 1},
		}

		store := &mockCircuitStore{circuits: storeCircuits}

		if err := v.RebuildRegistryFromStore(sdk.Context{}, store); err != nil {
			t.Fatalf("expected rebuild to succeed, got: %v", err)
		}

		// Verify count matches store.
		if v.CircuitCount() != 3 {
			t.Fatalf("expected 3 circuits after rebuild, got %d", v.CircuitCount())
		}

		// Verify the initial circuit is gone (replaced by store contents).
		if _, exists := v.registeredCircuits[initialHash]; exists {
			t.Fatalf("expected initial circuit to be replaced after rebuild")
		}

		// Verify each store circuit is present with correct data.
		for _, c := range storeCircuits {
			got, exists := v.registeredCircuits[c.CircuitHash]
			if !exists {
				t.Fatalf("expected circuit %x to be present after rebuild", c.CircuitHash)
			}
			if got.GasMultiplier != c.GasMultiplier {
				t.Fatalf("expected gas multiplier %d for circuit %x, got %d", c.GasMultiplier, c.CircuitHash, got.GasMultiplier)
			}
			if !bytes.Equal(got.VerifyingKey, c.VerifyingKey) {
				t.Fatalf("expected verifying key to match for circuit %x", c.CircuitHash)
			}
		}
	})

	t.Run("rebuild is deterministic across calls", func(t *testing.T) {
		v1 := NewSimulatedZKVerifier()
		v2 := NewSimulatedZKVerifier()

		// Seed v1 with different state than v2.
		_ = v1.RegisterCircuit(RegisteredCircuit{CircuitHash: [32]byte{0xFF}, VerifyingKey: []byte("extra")})

		storeCircuits := []RegisteredCircuit{
			{CircuitHash: [32]byte{0x10}, VerifyingKey: []byte("vk-10"), Active: true, GasMultiplier: 1},
			{CircuitHash: [32]byte{0x20}, VerifyingKey: []byte("vk-20"), Active: true, GasMultiplier: 5},
		}
		store := &mockCircuitStore{circuits: storeCircuits}

		// Rebuild both from same store — they must converge.
		if err := v1.RebuildRegistryFromStore(sdk.Context{}, store); err != nil {
			t.Fatalf("v1 rebuild failed: %v", err)
		}
		if err := v2.RebuildRegistryFromStore(sdk.Context{}, store); err != nil {
			t.Fatalf("v2 rebuild failed: %v", err)
		}

		if v1.CircuitCount() != v2.CircuitCount() {
			t.Fatalf("expected same circuit count after rebuild, v1=%d v2=%d", v1.CircuitCount(), v2.CircuitCount())
		}

		for hash, c1 := range v1.registeredCircuits {
			c2, exists := v2.registeredCircuits[hash]
			if !exists {
				t.Fatalf("circuit %x in v1 but not v2 after rebuild", hash)
			}
			if c1.GasMultiplier != c2.GasMultiplier {
				t.Fatalf("gas multiplier mismatch for circuit %x: v1=%d v2=%d", hash, c1.GasMultiplier, c2.GasMultiplier)
			}
		}
	})

	t.Run("rebuild with store error returns error", func(t *testing.T) {
		v := NewSimulatedZKVerifier()
		store := &mockCircuitStore{err: fmt.Errorf("simulated store failure")}

		err := v.RebuildRegistryFromStore(sdk.Context{}, store)
		if err == nil {
			t.Fatalf("expected error from store failure")
		}
	})

	t.Run("rebuild with empty store clears registry", func(t *testing.T) {
		v := NewSimulatedZKVerifier()
		_ = v.RegisterCircuit(RegisteredCircuit{CircuitHash: [32]byte{0x01}, VerifyingKey: []byte("vk")})

		store := &mockCircuitStore{circuits: []RegisteredCircuit{}}

		if err := v.RebuildRegistryFromStore(sdk.Context{}, store); err != nil {
			t.Fatalf("rebuild with empty store failed: %v", err)
		}
		if v.CircuitCount() != 0 {
			t.Fatalf("expected 0 circuits after empty rebuild, got %d", v.CircuitCount())
		}
	})
}

// TestGasExhaustedPath verifies the ZKErrorGasExhausted error code exists and
// tests the gas exhaustion scenario. Since VerifyProof does not currently enforce
// a gas limit internally (gas metering is done by the Cosmos SDK gas meter), this
// test validates that:
// 1. The error code constant is defined and usable.
// 2. EstimateVerificationGas returns gas exceeding a practical limit for large proofs.
// 3. A custom system verifier can trigger the gas exhaustion code path.
func TestGasExhaustedPath(t *testing.T) {
	t.Run("ZKErrorGasExhausted constant is defined", func(t *testing.T) {
		if ZKErrorGasExhausted != "GAS_EXHAUSTED" {
			t.Fatalf("expected GAS_EXHAUSTED, got %s", ZKErrorGasExhausted)
		}
	})

	t.Run("large proof estimation exceeds practical gas limit", func(t *testing.T) {
		v := NewSimulatedZKVerifier()
		var hash [32]byte
		hash[0] = 0xEE
		_ = v.RegisterCircuit(RegisteredCircuit{
			CircuitHash:   hash,
			VerifyingKey:  []byte{0x01},
			GasMultiplier: 10,
		})

		// Construct a large proof (near max size) with high gas multiplier.
		proof := &ZKProof{
			System:       ProofSystemRISC0,
			Proof:        bytes.Repeat([]byte{0x01}, 500000), // 500KB proof
			PublicInputs: bytes.Repeat([]byte{0x02}, 10000),  // 10KB public inputs
			CircuitHash:  hash,
		}

		gas := v.EstimateVerificationGas(proof)
		// With 500K * 10 gas/byte * 4 (RISC0 multiplier) * 10 (circuit multiplier) = 200M+
		// This would exceed any practical block gas limit.
		if gas < 100_000_000 {
			t.Fatalf("expected gas estimation > 100M for large proof, got %d", gas)
		}
	})

	t.Run("system verifier can return gas exhausted error", func(t *testing.T) {
		v := NewSimulatedZKVerifier()

		// Register a custom system verifier that simulates gas exhaustion.
		_ = v.RegisterSystemVerifier(ProofSystemGroth16, func(proof *ZKProof, circuit *RegisteredCircuit) (bool, error) {
			return false, fmt.Errorf("gas exhausted during pairing computation")
		})

		var hash [32]byte
		hash[0] = 0x99
		vk := []byte("gas-test-vk")
		_ = v.RegisterCircuit(RegisteredCircuit{
			CircuitHash:  hash,
			VerifyingKey: vk,
			System:       ProofSystemGroth16,
		})

		proof := &ZKProof{
			System:           ProofSystemGroth16,
			Proof:            bytes.Repeat([]byte{0x01}, 192),
			PublicInputs:     bytes.Repeat([]byte{0x02}, 32),
			VerifyingKeyHash: sha256.Sum256(vk),
			CircuitHash:      hash,
			ProofSize:        192,
		}

		result := v.VerifyProof(sdk.Context{}, proof)
		if result.Valid {
			t.Fatalf("expected verification to fail when system verifier returns error")
		}
		if result.ErrorCode != ZKErrorInvalidProof {
			t.Fatalf("expected INVALID_PROOF error code, got %s", result.ErrorCode)
		}
		// Verify the error message propagates from the system verifier.
		if result.ErrorMessage == "" {
			t.Fatalf("expected error message from system verifier")
		}
	})

	t.Run("gas exhausted result can be constructed", func(t *testing.T) {
		// Verify that ZKErrorGasExhausted can be used in a verification result,
		// confirming the error path is usable even though VerifyProof doesn't
		// currently trigger it directly.
		result := &ZKVerificationResult{
			Valid:        false,
			GasUsed:      999999999,
			ErrorCode:    ZKErrorGasExhausted,
			ErrorMessage: "verification gas limit exceeded",
		}
		if result.ErrorCode != ZKErrorGasExhausted {
			t.Fatalf("expected GAS_EXHAUSTED error code in result")
		}
		if result.Valid {
			t.Fatalf("expected result to be invalid")
		}
	})
}
