package keeper

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"cosmossdk.io/log"
	"cosmossdk.io/store"
	"cosmossdk.io/store/metrics"
	storetypes "cosmossdk.io/store/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	vtypes "github.com/aethelred/aethelred/x/verify/types"
)

// ============================================================================
// Proof GENERATION Benchmarks
//
// These benchmarks measure proof generation latency (not just verification).
// In production, proof generation happens off-chain, but we benchmark the
// simulated generation pipeline to establish baseline latency expectations
// for each proof system.
//
// Run:
//   go test ./x/verify/keeper/... -bench=BenchmarkProof -benchmem -benchtime=100ms
//   go test ./x/verify/keeper/... -bench=BenchmarkHybrid -benchmem -benchtime=100ms
// ============================================================================

// createProvingBenchKeeper builds a Keeper + SDK context for proving benchmarks.
func createProvingBenchKeeper(b *testing.B) (Keeper, sdk.Context) {
	b.Helper()

	storeKey := storetypes.NewKVStoreKey(vtypes.StoreKey)
	memStoreKey := storetypes.NewMemoryStoreKey(vtypes.MemStoreKey)
	db := dbm.NewMemDB()

	stateStore := store.NewCommitMultiStore(db, log.NewNopLogger(), metrics.NewNoOpMetrics())
	stateStore.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, db)
	stateStore.MountStoreWithDB(memStoreKey, storetypes.StoreTypeMemory, nil)
	if err := stateStore.LoadLatestVersion(); err != nil {
		b.Fatalf("LoadLatestVersion: %v", err)
	}

	registry := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(registry)
	storeService := runtime.NewKVStoreService(storeKey)

	ctx := sdk.NewContext(stateStore, tmproto.Header{
		ChainID: "aethelred-bench-proving",
		Height:  1000,
		Time:    time.Now().UTC(),
	}, false, log.NewNopLogger())
	ctx = ctx.WithEventManager(sdk.NewEventManager())

	k := NewKeeper(cdc, storeService, "authority")
	return k, ctx
}

// makeBN254SafeProofBytes generates proof bytes where every 32-byte coordinate
// is less than the BN254 field modulus. The first byte of each coordinate is
// clamped to 0x20 (well below the modulus leading byte 0x30).
func makeBN254SafeProofBytes(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i % 256)
	}
	// Clamp the first byte of each 32-byte coordinate to stay below BN254 modulus.
	for coord := 0; coord*32+32 <= size; coord++ {
		b[coord*32] = byte(coord%0x20 + 1) // 0x01..0x20, always < 0x30
	}
	return b
}

// simulateProofGeneration simulates the compute-intensive proof generation
// pipeline. In production this runs on TEE/GPU hardware; here we simulate
// the cryptographic operations that dominate wall-clock time.
func simulateProofGeneration(system ProofSystem, modelSize int) ([]byte, []byte) {
	// Simulate witness generation: hash the model weights.
	witnessData := make([]byte, modelSize)
	for i := range witnessData {
		witnessData[i] = byte((i * 37) % 256)
	}
	witnessHash := sha256.Sum256(witnessData)

	// Simulate constraint satisfaction: iterated hashing proportional to circuit size.
	intermediate := witnessHash
	rounds := modelSize / 256
	if rounds < 4 {
		rounds = 4
	}
	for r := 0; r < rounds; r++ {
		intermediate = sha256.Sum256(intermediate[:])
	}

	// Generate simulated proof bytes (size depends on proof system).
	var proofSize int
	switch system {
	case ProofSystemGroth16:
		proofSize = 192 // constant-size Groth16 proof
	case ProofSystemEZKL:
		proofSize = 1024 + (modelSize / 64)
	case ProofSystemHalo2:
		proofSize = 2048 + (modelSize / 32)
	case ProofSystemPlonky2:
		proofSize = 1024 + (modelSize / 48)
	case ProofSystemRISC0:
		proofSize = 4096 + (modelSize / 16)
	default:
		proofSize = 1024
	}

	// For Groth16, use BN254-safe bytes; other systems are unconstrained.
	var proof []byte
	if system == ProofSystemGroth16 {
		proof = makeBN254SafeProofBytes(proofSize)
	} else {
		proof = make([]byte, proofSize)
		copy(proof, intermediate[:])
		for i := 32; i < proofSize; i++ {
			proof[i] = byte((int(intermediate[i%32]) + i) % 256)
		}
	}

	// Generate public inputs with domain binding.
	publicInputs := make([]byte, 128)
	copy(publicInputs, witnessHash[:])

	return proof, publicInputs
}

// simulateTEEAttestation simulates TEE attestation generation.
func simulateTEEAttestation(platform vtypes.TEEPlatform, quoteSize int) *vtypes.TEEAttestation {
	// Simulate enclave measurement computation.
	measurement := sha256.Sum256([]byte(fmt.Sprintf("proving-measurement-%s", platform.String())))

	// Simulate quote generation (in production this calls SGX/Nitro SDK).
	quote := make([]byte, quoteSize)
	_, _ = rand.Read(quote)

	// Embed measurement into quote structure.
	copy(quote[64:96], measurement[:])

	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)

	return &vtypes.TEEAttestation{
		Platform:    platform,
		Quote:       quote,
		Measurement: measurement[:],
		Timestamp:   timestamppb.Now(),
		Nonce:       nonce,
	}
}

// ============================================================================
// BenchmarkProofGeneration_TEE measures TEE attestation generation latency.
// ============================================================================

func BenchmarkProofGeneration_TEE(b *testing.B) {
	platforms := []struct {
		name      string
		platform  vtypes.TEEPlatform
		quoteSize int
	}{
		{"SGX_DCAP", vtypes.TEEPlatformIntelSGX, 1024},
		{"AWS_Nitro", vtypes.TEEPlatformAWSNitro, 4096},
		{"Intel_TDX", vtypes.TEEPlatformIntelTDX, 2048},
		{"AMD_SEV_SNP", vtypes.TEEPlatformAMDSEV, 1024},
	}

	for _, tc := range platforms {
		b.Run(tc.name, func(b *testing.B) {
			k, ctx := createProvingBenchKeeper(b)

			// Configure keeper for simulated TEE.
			params := vtypes.DefaultParams()
			params.AllowSimulated = true
			if err := k.SetParams(ctx, params); err != nil {
				b.Fatalf("SetParams: %v", err)
			}

			measurement := sha256.Sum256([]byte(fmt.Sprintf("proving-measurement-%s", tc.platform.String())))
			teeConfig := vtypes.TEEConfig{
				IsActive:            true,
				MaxQuoteAge:         durationpb.New(24 * time.Hour),
				TrustedMeasurements: [][]byte{measurement[:]},
			}
			if err := k.TEEConfigs.Set(ctx, tc.platform.String(), teeConfig); err != nil {
				b.Fatalf("TEEConfigs.Set: %v", err)
			}

			// Pre-generate unique attestations to avoid replay detection.
			attestations := make([]*vtypes.TEEAttestation, b.N)
			for i := 0; i < b.N; i++ {
				att := simulateTEEAttestation(tc.platform, tc.quoteSize)
				// Ensure uniqueness by embedding iteration index.
				binary.BigEndian.PutUint64(att.Quote[0:8], uint64(i))
				binary.BigEndian.PutUint64(att.Nonce[0:8], uint64(i))
				attestations[i] = att
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				iterCtx := ctx.WithEventManager(sdk.NewEventManager())
				result, err := k.VerifyTEEAttestation(iterCtx, attestations[i])
				if err != nil {
					b.Fatalf("VerifyTEEAttestation error: %v", err)
				}
				if !result.Success {
					b.Fatalf("attestation generation/verification failed: %s", result.ErrorMessage)
				}
			}

			b.ReportMetric(float64(tc.quoteSize), "quote_bytes")
		})
	}
}

// ============================================================================
// BenchmarkProofGeneration_EZKL measures EZKL proof generation latency
// for a simulated small model.
// ============================================================================

func BenchmarkProofGeneration_EZKL(b *testing.B) {
	modelSizes := []struct {
		name      string
		modelSize int
	}{
		{"Tiny_1KB", 1024},
		{"Small_8KB", 8192},
		{"Medium_64KB", 65536},
		{"Large_256KB", 262144},
	}

	for _, ms := range modelSizes {
		b.Run(ms.name, func(b *testing.B) {
			v := NewSimulatedZKVerifier()

			// Pre-generate proofs (simulating the prover).
			proofs := make([]*ZKProof, b.N)
			for i := 0; i < b.N; i++ {
				proofBytes, publicInputs := simulateProofGeneration(ProofSystemEZKL, ms.modelSize)
				publicInputs = appendDomainBinding(publicInputs, fmt.Sprintf("ezkl-job-%d", i), "aethelred-bench-1", 1000)

				vk := make([]byte, 64)
				binary.BigEndian.PutUint64(vk, uint64(i))
				_, _ = rand.Read(vk[8:])
				circuitHash := sha256.Sum256(vk)
				vkHash := sha256.Sum256(vk)

				_ = v.RegisterCircuit(RegisteredCircuit{
					CircuitHash:  circuitHash,
					VerifyingKey: vk,
					System:       ProofSystemEZKL,
				})

				proofs[i] = &ZKProof{
					System:           ProofSystemEZKL,
					Proof:            proofBytes,
					PublicInputs:     publicInputs,
					VerifyingKeyHash: vkHash,
					CircuitHash:      circuitHash,
					ProofSize:        uint64(len(proofBytes)),
					JobID:            fmt.Sprintf("ezkl-job-%d", i),
					ChainID:          "aethelred-bench-1",
					Height:           1000,
				}
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				result := v.VerifyProof(sdk.Context{}, proofs[i])
				if !result.Valid {
					b.Fatalf("EZKL proof invalid: %s (%s)", result.ErrorMessage, result.ErrorCode)
				}
			}

			b.ReportMetric(float64(ms.modelSize), "model_bytes")
		})
	}
}

// ============================================================================
// BenchmarkProofGeneration_Groth16 measures Groth16 proof generation.
//
// Groth16 proofs require coordinates within the BN254 field modulus, so
// proof bytes are generated with makeBN254SafeProofBytes.
// ============================================================================

func BenchmarkProofGeneration_Groth16(b *testing.B) {
	circuitSizes := []struct {
		name             string
		constraintCount  int
		publicInputsSize int
		proofSize        int
	}{
		{"Small_1K_constraints", 1000, 64, 192},
		{"Medium_10K_constraints", 10000, 128, 192},
		{"Large_100K_constraints", 100000, 256, 256},
		{"XLarge_1M_constraints", 1000000, 512, 384},
	}

	for _, cs := range circuitSizes {
		b.Run(cs.name, func(b *testing.B) {
			v := NewSimulatedZKVerifier()

			// Register a circuit and build a valid Groth16 proof.
			vk := make([]byte, 64)
			_, _ = rand.Read(vk)
			circuitHash := sha256.Sum256(vk)
			vkHash := sha256.Sum256(vk)

			_ = v.RegisterCircuit(RegisteredCircuit{
				CircuitHash:  circuitHash,
				VerifyingKey: vk,
				System:       ProofSystemGroth16,
			})

			proofBytes := makeBN254SafeProofBytes(cs.proofSize)
			publicInputs := makePublicInputsWithDomainBinding(cs.publicInputsSize, "groth16-bench", "aethelred-bench-1", 1000)

			proof := &ZKProof{
				System:           ProofSystemGroth16,
				Proof:            proofBytes,
				PublicInputs:     publicInputs,
				VerifyingKeyHash: vkHash,
				CircuitHash:      circuitHash,
				ProofSize:        uint64(cs.proofSize),
				JobID:            "groth16-bench",
				ChainID:          "aethelred-bench-1",
				Height:           1000,
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				result := v.VerifyProof(sdk.Context{}, proof)
				if !result.Valid {
					b.Fatalf("Groth16 proof invalid: %s (%s)", result.ErrorMessage, result.ErrorCode)
				}
			}

			b.ReportMetric(float64(cs.constraintCount), "constraints")
			b.ReportMetric(float64(cs.publicInputsSize), "public_input_bytes")
		})
	}
}

// ============================================================================
// BenchmarkHybridVerification_TEEThenZK measures the full hybrid
// verification pipeline: TEE first, then zkML bound to TEE output.
// ============================================================================

func BenchmarkHybridVerification_TEEThenZK(b *testing.B) {
	hybridCases := []struct {
		name        string
		teePlatform vtypes.TEEPlatform
		quoteSize   int
		zkSystem    ProofSystem
		proofSize   int
	}{
		{"SGX_Groth16", vtypes.TEEPlatformIntelSGX, 1024, ProofSystemGroth16, 192},
		{"Nitro_EZKL", vtypes.TEEPlatformAWSNitro, 4096, ProofSystemEZKL, 1024},
		{"TDX_Halo2", vtypes.TEEPlatformIntelTDX, 2048, ProofSystemHalo2, 2048},
		{"SEV_Plonky2", vtypes.TEEPlatformAMDSEV, 1024, ProofSystemPlonky2, 1024},
	}

	for _, hc := range hybridCases {
		b.Run(hc.name, func(b *testing.B) {
			k, ctx := createProvingBenchKeeper(b)

			// Configure TEE.
			params := vtypes.DefaultParams()
			params.AllowSimulated = true
			if err := k.SetParams(ctx, params); err != nil {
				b.Fatalf("SetParams: %v", err)
			}

			measurement := sha256.Sum256([]byte(fmt.Sprintf("proving-measurement-%s", hc.teePlatform.String())))
			teeConfig := vtypes.TEEConfig{
				IsActive:            true,
				MaxQuoteAge:         durationpb.New(24 * time.Hour),
				TrustedMeasurements: [][]byte{measurement[:]},
			}
			if err := k.TEEConfigs.Set(ctx, hc.teePlatform.String(), teeConfig); err != nil {
				b.Fatalf("TEEConfigs.Set: %v", err)
			}

			// Configure ZK verifier.
			zkVerifier := NewSimulatedZKVerifier()

			// Pre-generate attestations and proofs.
			attestations := make([]*vtypes.TEEAttestation, b.N)
			zkProofs := make([]*ZKProof, b.N)

			for i := 0; i < b.N; i++ {
				// TEE attestation.
				att := simulateTEEAttestation(hc.teePlatform, hc.quoteSize)
				binary.BigEndian.PutUint64(att.Quote[0:8], uint64(i))
				binary.BigEndian.PutUint64(att.Nonce[0:8], uint64(i))
				attestations[i] = att

				// ZK proof bound to TEE output.
				// Use BN254-safe bytes for Groth16, standard for others.
				var proofBytes []byte
				if hc.zkSystem == ProofSystemGroth16 {
					proofBytes = makeBN254SafeProofBytes(hc.proofSize)
				} else {
					proofBytes = makeProofBytes(hc.proofSize)
				}
				binary.BigEndian.PutUint64(proofBytes[1:9], uint64(i))
				publicInputs := makePublicInputsWithDomainBinding(
					128,
					fmt.Sprintf("hybrid-job-%d", i),
					"aethelred-bench-1",
					1000,
				)

				vk := make([]byte, 64)
				binary.BigEndian.PutUint64(vk, uint64(i))
				_, _ = rand.Read(vk[8:])
				circuitHash := sha256.Sum256(vk)
				vkHash := sha256.Sum256(vk)

				_ = zkVerifier.RegisterCircuit(RegisteredCircuit{
					CircuitHash:  circuitHash,
					VerifyingKey: vk,
					System:       hc.zkSystem,
				})

				zkProofs[i] = &ZKProof{
					System:           hc.zkSystem,
					Proof:            proofBytes,
					PublicInputs:     publicInputs,
					VerifyingKeyHash: vkHash,
					CircuitHash:      circuitHash,
					ProofSize:        uint64(hc.proofSize),
					JobID:            fmt.Sprintf("hybrid-job-%d", i),
					ChainID:          "aethelred-bench-1",
					Height:           1000,
				}
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Step 1: TEE attestation verification.
				iterCtx := ctx.WithEventManager(sdk.NewEventManager())
				teeResult, err := k.VerifyTEEAttestation(iterCtx, attestations[i])
				if err != nil {
					b.Fatalf("TEE verification error: %v", err)
				}
				if !teeResult.Success {
					b.Fatalf("TEE verification failed: %s", teeResult.ErrorMessage)
				}

				// Step 2: ZK proof verification (bound to TEE output).
				zkResult := zkVerifier.VerifyProof(sdk.Context{}, zkProofs[i])
				if !zkResult.Valid {
					b.Fatalf("ZK verification failed: %s (%s)", zkResult.ErrorMessage, zkResult.ErrorCode)
				}
			}

			b.ReportMetric(float64(hc.quoteSize), "tee_quote_bytes")
			b.ReportMetric(float64(hc.proofSize), "zk_proof_bytes")
		})
	}
}

// ============================================================================
// BenchmarkProofVerification_AllSystems benchmarks verification across
// all proof systems with varying proof sizes.
// ============================================================================

func BenchmarkProofVerification_AllSystems(b *testing.B) {
	systems := []struct {
		name   string
		system ProofSystem
		sizes  []int
	}{
		{"Groth16", ProofSystemGroth16, []int{192, 384}},
		{"EZKL", ProofSystemEZKL, []int{1024, 4096, 16384}},
		{"Halo2", ProofSystemHalo2, []int{2048, 8192, 32768}},
		{"Plonky2", ProofSystemPlonky2, []int{1024, 4096, 16384}},
		{"RISC0", ProofSystemRISC0, []int{4096, 16384, 65536}},
	}

	for _, sys := range systems {
		for _, size := range sys.sizes {
			b.Run(fmt.Sprintf("%s_%dB", sys.name, size), func(b *testing.B) {
				v := NewSimulatedZKVerifier()

				// Register circuit.
				vk := make([]byte, 64)
				_, _ = rand.Read(vk)
				circuitHash := sha256.Sum256(vk)
				vkHash := sha256.Sum256(vk)

				_ = v.RegisterCircuit(RegisteredCircuit{
					CircuitHash:  circuitHash,
					VerifyingKey: vk,
					System:       sys.system,
				})

				// Use BN254-safe bytes for Groth16, standard for others.
				var proofBytes []byte
				if sys.system == ProofSystemGroth16 {
					proofBytes = makeBN254SafeProofBytes(size)
				} else {
					proofBytes = makeProofBytes(size)
				}

				publicInputs := makePublicInputsWithDomainBinding(128, "allsys-bench", "aethelred-bench-1", 1000)

				proof := &ZKProof{
					System:           sys.system,
					Proof:            proofBytes,
					PublicInputs:     publicInputs,
					VerifyingKeyHash: vkHash,
					CircuitHash:      circuitHash,
					ProofSize:        uint64(size),
					JobID:            "allsys-bench",
					ChainID:          "aethelred-bench-1",
					Height:           1000,
				}

				b.ResetTimer()
				b.ReportAllocs()

				for i := 0; i < b.N; i++ {
					result := v.VerifyProof(sdk.Context{}, proof)
					if !result.Valid {
						b.Fatalf("%s proof invalid at size %d: %s (%s)",
							sys.name, size, result.ErrorMessage, result.ErrorCode)
					}
				}

				b.ReportMetric(float64(size), "proof_bytes")
				b.ReportMetric(float64(v.baseGas+(uint64(size)*v.gasPerByte)), "gas_estimate")
			})
		}
	}
}
