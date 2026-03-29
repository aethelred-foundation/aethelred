package keeper

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// =============================================================================
// SQ15 — zkML Latency and Cost Optimization: Go-side benchmarks
//
// These benchmarks baseline the on-chain zkML verification path so we can
// identify the top optimization targets before mainnet.
//
// Run:
//   go test ./x/verify/keeper/... -bench=BenchmarkZKML -benchmem -count=3
// =============================================================================

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// makeProofBytes returns deterministic pseudo-random proof bytes of the given size.
func makeProofBytes(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i % 256)
	}
	return b
}

// makePublicInputsWithDomainBinding constructs public inputs that include a
// trailing 32-byte domain-binding digest (jobID || chainID || height).
func makePublicInputsWithDomainBinding(payloadSize int, jobID, chainID string, height int64) []byte {
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte((i + 42) % 256)
	}
	digest := computeDomainBindingDigest(jobID, chainID, height)
	return append(payload, digest[:]...)
}

// registerBenchCircuit sets up a circuit in the verifier and returns a
// ZKProof ready for simulated verification.
func registerBenchCircuit(v *ZKVerifier, system ProofSystem, proofSize, publicInputsPayload int) *ZKProof {
	vk := make([]byte, 64)
	_, _ = rand.Read(vk)
	circuitHash := sha256.Sum256(vk)
	vkHash := sha256.Sum256(vk)

	_ = v.RegisterCircuit(RegisteredCircuit{
		CircuitHash:  circuitHash,
		VerifyingKey: vk,
		System:       system,
	})

	proof := makeProofBytes(proofSize)
	publicInputs := makePublicInputsWithDomainBinding(publicInputsPayload, "bench-job-1", "bench-chain-1", 100)

	return &ZKProof{
		System:           system,
		Proof:            proof,
		PublicInputs:     publicInputs,
		VerifyingKeyHash: vkHash,
		CircuitHash:      circuitHash,
		ProofSize:        uint64(proofSize),
		JobID:            "bench-job-1",
		ChainID:          "bench-chain-1",
		Height:           100,
	}
}

// ---------------------------------------------------------------------------
// BenchmarkZKMLVerification — end-to-end verification path per proof system
// ---------------------------------------------------------------------------

func BenchmarkZKMLVerification(b *testing.B) {
	systems := []struct {
		name      string
		system    ProofSystem
		proofSize int
	}{
		{"Groth16_192B", ProofSystemGroth16, 192},
		{"EZKL_1KB", ProofSystemEZKL, 1024},
		{"Halo2_2KB", ProofSystemHalo2, 2048},
		{"Plonky2_1KB", ProofSystemPlonky2, 1024},
		{"RISC0_4KB", ProofSystemRISC0, 4096},
		{"Groth16_4KB", ProofSystemGroth16, 4096},
		{"EZKL_16KB", ProofSystemEZKL, 16384},
		{"Halo2_32KB", ProofSystemHalo2, 32768},
	}

	for _, tc := range systems {
		b.Run(tc.name, func(b *testing.B) {
			v := NewSimulatedZKVerifier()
			proof := registerBenchCircuit(v, tc.system, tc.proofSize, 128)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				result := v.VerifyProof(sdk.Context{}, proof)
				if !result.Valid {
					b.Fatalf("expected valid proof, got error: %s (%s)", result.ErrorMessage, result.ErrorCode)
				}
			}

			b.ReportMetric(float64(tc.proofSize), "proof_bytes")
			b.ReportMetric(float64(v.baseGas+(uint64(tc.proofSize)*v.gasPerByte)), "gas_estimate")
		})
	}
}

// ---------------------------------------------------------------------------
// BenchmarkZKMLProofParsing — proof deserialization / structural validation
// ---------------------------------------------------------------------------

func BenchmarkZKMLProofParsing(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"192B", 192},
		{"1KB", 1024},
		{"4KB", 4096},
		{"16KB", 16384},
		{"64KB", 65536},
		{"256KB", 262144},
	}

	for _, tc := range sizes {
		b.Run(tc.name, func(b *testing.B) {
			proofBytes := makeProofBytes(tc.size)
			publicInputs := make([]byte, 128)
			var vkHash [32]byte
			copy(vkHash[:], bytes.Repeat([]byte{0xAB}, 32))

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Simulate the proof parsing / structural validation path.
				proof := &ZKProof{
					System:           ProofSystemGroth16,
					Proof:            proofBytes,
					PublicInputs:     publicInputs,
					VerifyingKeyHash: vkHash,
					ProofSize:        uint64(tc.size),
				}

				// ZK-01: Size validation on actual bytes
				actualSize := uint64(len(proof.Proof))
				if actualSize > 1048576 {
					b.Fatal("oversized")
				}
				if proof.ProofSize != 0 && proof.ProofSize != actualSize {
					b.Fatal("size mismatch")
				}

				// SHA-256 of proof bytes (used for indexing / dedup)
				_ = sha256.Sum256(proof.Proof)

				// SHA-256 of public inputs
				_ = sha256.Sum256(proof.PublicInputs)
			}

			b.ReportMetric(float64(tc.size), "proof_bytes")
		})
	}
}

// ---------------------------------------------------------------------------
// BenchmarkZKMLCircuitLookup — circuit registry lookup performance
// ---------------------------------------------------------------------------

func BenchmarkZKMLCircuitLookup(b *testing.B) {
	counts := []struct {
		name  string
		count int
	}{
		{"10_circuits", 10},
		{"100_circuits", 100},
		{"1000_circuits", 1000},
		{"10000_circuits", 10000},
	}

	for _, tc := range counts {
		b.Run(tc.name, func(b *testing.B) {
			v := NewSimulatedZKVerifier()

			// Pre-populate the registry with N circuits.
			var targetHash [32]byte
			for i := 0; i < tc.count; i++ {
				vk := make([]byte, 64)
				binary.BigEndian.PutUint64(vk, uint64(i))
				h := sha256.Sum256(vk)
				_ = v.RegisterCircuit(RegisteredCircuit{
					CircuitHash:  h,
					VerifyingKey: vk,
					System:       ProofSystemGroth16,
				})
				if i == tc.count/2 {
					targetHash = h
				}
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				circuit, exists := v.registeredCircuits[targetHash]
				if !exists {
					b.Fatal("circuit not found")
				}
				if !circuit.Active {
					b.Fatal("circuit inactive")
				}
			}

			b.ReportMetric(float64(tc.count), "registry_size")
		})
	}
}

// ---------------------------------------------------------------------------
// BenchmarkZKMLDomainBinding — domain binding digest computation
// ---------------------------------------------------------------------------

func BenchmarkZKMLDomainBinding(b *testing.B) {
	b.Run("ComputeDigest", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = computeDomainBindingDigest("job-12345", "aethelred-testnet-1", 500000)
		}
	})

	b.Run("ValidateBinding", func(b *testing.B) {
		v := NewZKVerifier()
		jobID := "job-12345"
		chainID := "aethelred-testnet-1"
		height := int64(500000)
		publicInputs := makePublicInputsWithDomainBinding(128, jobID, chainID, height)

		proof := &ZKProof{
			System:       ProofSystemGroth16,
			Proof:        makeProofBytes(192),
			PublicInputs: publicInputs,
			JobID:        jobID,
			ChainID:      chainID,
			Height:       height,
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			err := v.validateDomainBinding(proof)
			if err != nil {
				b.Fatalf("unexpected error: %v", err)
			}
		}
	})

	b.Run("AppendBinding", func(b *testing.B) {
		base := make([]byte, 128)
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = appendDomainBinding(base, "job-12345", "aethelred-testnet-1", 500000)
		}
	})
}

// ---------------------------------------------------------------------------
// BenchmarkZKMLGasCost — gas computation path
// ---------------------------------------------------------------------------

func BenchmarkZKMLGasCost(b *testing.B) {
	sizes := []int{192, 1024, 4096, 16384, 65536}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			v := NewZKVerifier()
			actualSize := uint64(size)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				gas := v.baseGas + (actualSize * v.gasPerByte)
				gas *= 1 // default multiplier
				_ = gas
			}
		})
	}
}
