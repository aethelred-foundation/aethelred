package keeper

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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

// ════════════════════════════════════════════════════════════════════════
// SQ14 — TEE Latency Baseline Benchmarks
//
// These benchmarks establish p50/p95/p99 baselines for TEE verification
// hot paths. They run in simulated mode (no real SGX/Nitro hardware).
//
// Run:
//   go test ./x/verify/keeper/... -bench=BenchmarkTEE -benchmem -count=3
// ════════════════════════════════════════════════════════════════════════

// createBenchKeeper builds a minimal Keeper + SDK context for benchmarks.
// It uses an in-memory store and simulated TEE mode.
func createBenchKeeper(b *testing.B) (Keeper, sdk.Context) {
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
		ChainID: "aethelred-bench-tee",
		Height:  1000,
		Time:    time.Now().UTC(),
	}, false, log.NewNopLogger())
	ctx = ctx.WithEventManager(sdk.NewEventManager())

	k := NewKeeper(cdc, storeService, "authority")
	return k, ctx
}

// setupTEEBenchEnv configures the keeper with simulated TEE params and
// registers a TEE config for the given platform. Returns a well-formed
// attestation ready for verification.
func setupTEEBenchEnv(b *testing.B, platform vtypes.TEEPlatform, quoteSize int) (Keeper, sdk.Context, *vtypes.TEEAttestation) {
	b.Helper()

	k, ctx := createBenchKeeper(b)

	// Set params: simulated mode ON.
	params := vtypes.DefaultParams()
	params.AllowSimulated = true
	if err := k.SetParams(ctx, params); err != nil {
		b.Fatalf("SetParams: %v", err)
	}

	// Generate a deterministic measurement.
	measurement := sha256.Sum256([]byte(fmt.Sprintf("bench-measurement-%s", platform.String())))

	// Register TEE config with the measurement as trusted.
	teeConfig := vtypes.TEEConfig{
		IsActive:            true,
		MaxQuoteAge:         durationpb.New(24 * time.Hour),
		TrustedMeasurements: [][]byte{measurement[:]},
	}
	if err := k.TEEConfigs.Set(ctx, platform.String(), teeConfig); err != nil {
		b.Fatalf("TEEConfigs.Set: %v", err)
	}

	// Return a template attestation (callers needing unique quotes per
	// iteration will build their own from this context).
	quote := make([]byte, quoteSize)
	for i := range quote {
		quote[i] = byte(i % 251)
	}
	nonce := make([]byte, 32)
	nonce[0] = 0x42

	attestation := &vtypes.TEEAttestation{
		Platform:    platform,
		Quote:       quote,
		Measurement: measurement[:],
		Timestamp:   timestamppb.New(ctx.BlockTime().Add(-1 * time.Minute)),
		Nonce:       nonce,
	}

	return k, ctx, attestation
}

// ────────────────────────────────────────────────────────────────────────
// BenchmarkTEEVerification — full TEE attestation verification path
// ────────────────────────────────────────────────────────────────────────

func BenchmarkTEEVerification(b *testing.B) {
	platforms := []struct {
		name      string
		platform  vtypes.TEEPlatform
		quoteSize int
	}{
		{"SGX", vtypes.TEEPlatformIntelSGX, 1024},
		{"Nitro", vtypes.TEEPlatformAWSNitro, 4096},
		{"TDX", vtypes.TEEPlatformIntelTDX, 2048},
		{"SEV", vtypes.TEEPlatformAMDSEV, 1024},
	}

	for _, tc := range platforms {
		b.Run(tc.name, func(b *testing.B) {
			k, ctx, _ := setupTEEBenchEnv(b, tc.platform, tc.quoteSize)

			// Pre-generate unique quotes/nonces for each iteration to avoid
			// replay detection (each quote hash must be unique).
			quotes := make([][]byte, b.N)
			nonces := make([][]byte, b.N)
			measurement := sha256.Sum256([]byte(fmt.Sprintf("bench-measurement-%s", tc.platform.String())))
			for i := 0; i < b.N; i++ {
				q := make([]byte, tc.quoteSize)
				for j := range q {
					q[j] = byte((i + j) % 251)
				}
				// Embed iteration index to ensure uniqueness.
				binary.BigEndian.PutUint64(q[0:8], uint64(i))
				quotes[i] = q

				n := make([]byte, 32)
				binary.BigEndian.PutUint64(n[0:8], uint64(i))
				binary.BigEndian.PutUint64(n[8:16], uint64(i*7+3))
				nonces[i] = n
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				att := &vtypes.TEEAttestation{
					Platform:    tc.platform,
					Quote:       quotes[i],
					Measurement: measurement[:],
					Timestamp:   timestamppb.New(ctx.BlockTime().Add(-1 * time.Minute)),
					Nonce:       nonces[i],
				}
				// Fresh event manager each iteration to avoid accumulation.
				iterCtx := ctx.WithEventManager(sdk.NewEventManager())
				result, err := k.VerifyTEEAttestation(iterCtx, att)
				if err != nil {
					b.Fatalf("VerifyTEEAttestation error: %v", err)
				}
				if !result.Success {
					b.Fatalf("verification failed: %s", result.ErrorMessage)
				}
			}
		})
	}
}

// ────────────────────────────────────────────────────────────────────────
// BenchmarkTEEAttestationParsing — attestation structural validation
// ────────────────────────────────────────────────────────────────────────

func BenchmarkTEEAttestationParsing(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"Small_1KB", 1024},
		{"Medium_4KB", 4096},
		{"Large_16KB", 16384},
	}

	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			measurement := sha256.Sum256([]byte("bench-parse"))
			quote := make([]byte, sz.size)
			for i := range quote {
				quote[i] = byte(i % 251)
			}

			att := &vtypes.TEEAttestation{
				Platform:    vtypes.TEEPlatformIntelSGX,
				Quote:       quote,
				Measurement: measurement[:],
				Timestamp:   timestamppb.Now(),
				Nonce:       []byte("bench-nonce-1234567890123456"),
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				if err := att.Validate(); err != nil {
					b.Fatalf("Validate: %v", err)
				}
			}
		})
	}

	// Sub-benchmark: platform-specific structural validation.
	b.Run("PlatformAdapters", func(b *testing.B) {
		adapters := []struct {
			name     string
			fn       func(*vtypes.TEEAttestation) (bool, error)
			minQuote int
		}{
			{"SGX_432B", verifyIntelSGXAttestation, 432},
			{"Nitro_1000B", verifyAWSNitroAttestation, 1000},
			{"TDX_584B", verifyIntelTDXAttestation, 584},
			{"SEV_672B", verifyAMDSEVAttestation, 672},
		}

		for _, a := range adapters {
			b.Run(a.name, func(b *testing.B) {
				quote := make([]byte, a.minQuote+512)
				for i := range quote {
					quote[i] = byte((i + 7) % 251)
				}

				att := &vtypes.TEEAttestation{
					Platform:    vtypes.TEEPlatformIntelSGX,
					Quote:       quote,
					Measurement: make([]byte, 32),
				}

				b.ResetTimer()
				b.ReportAllocs()

				for i := 0; i < b.N; i++ {
					ok, err := a.fn(att)
					if err != nil || !ok {
						b.Fatalf("adapter failed: ok=%v err=%v", ok, err)
					}
				}
			})
		}
	})
}

// ────────────────────────────────────────────────────────────────────────
// BenchmarkTEEMeasurementLookup — measurement registry lookup
// ────────────────────────────────────────────────────────────────────────

func BenchmarkTEEMeasurementLookup(b *testing.B) {
	// Test measurement lookup with varying registry sizes.
	registrySizes := []int{1, 10, 50, 100}

	for _, regSize := range registrySizes {
		b.Run(fmt.Sprintf("RegistrySize_%d", regSize), func(b *testing.B) {
			// Build a list of trusted measurements.
			trustedMeasurements := make([][]byte, regSize)
			for i := 0; i < regSize; i++ {
				m := sha256.Sum256([]byte(fmt.Sprintf("trusted-measurement-%d", i)))
				trustedMeasurements[i] = m[:]
			}

			// The target measurement is the LAST one (worst-case linear scan).
			targetMeasurement := trustedMeasurements[regSize-1]

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				found := false
				for _, trusted := range trustedMeasurements {
					if bytes.Equal(trusted, targetMeasurement) {
						found = true
						break
					}
				}
				if !found {
					b.Fatal("measurement not found")
				}
			}
		})
	}

	// Sub-benchmark: measurement config JSON parsing (cross-layer config).
	b.Run("ConfigParsing", func(b *testing.B) {
		configJSON := buildBenchMeasurementConfig(10, 5)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := ParseTrustedMeasurementsJSON(configJSON)
			if err != nil {
				b.Fatalf("ParseTrustedMeasurementsJSON: %v", err)
			}
		}
	})

	// Sub-benchmark: hex decode of measurements.
	b.Run("HexDecode", func(b *testing.B) {
		hexStr := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := hex.DecodeString(hexStr)
			if err != nil {
				b.Fatalf("hex.DecodeString: %v", err)
			}
		}
	})

	// Sub-benchmark: DecodeMeasurements from parsed config.
	b.Run("DecodeMeasurements", func(b *testing.B) {
		configJSON := buildBenchMeasurementConfig(5, 3)
		parsed, err := ParseTrustedMeasurementsJSON(configJSON)
		if err != nil {
			b.Fatalf("setup: %v", err)
		}

		// Pick a key that exists.
		var key string
		for k := range parsed {
			key = k
			break
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := DecodeMeasurements(parsed, key)
			if err != nil {
				b.Fatalf("DecodeMeasurements: %v", err)
			}
		}
	})
}

// buildBenchMeasurementConfig generates a measurement config JSON with the
// specified number of platforms and measurements per platform.
func buildBenchMeasurementConfig(platforms, measurementsPerPlatform int) []byte {
	type configFile struct {
		Version      int                            `json:"version"`
		Measurements map[string]map[string][]string `json:"measurements"`
	}

	cfg := configFile{
		Version:      1,
		Measurements: make(map[string]map[string][]string),
	}

	for p := 0; p < platforms; p++ {
		platformName := fmt.Sprintf("platform-%d", p)
		fields := make(map[string][]string)
		for m := 0; m < measurementsPerPlatform; m++ {
			fieldName := fmt.Sprintf("field-%d", m)
			var hexValues []string
			for v := 0; v < 3; v++ {
				h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", platformName, fieldName, v)))
				hexValues = append(hexValues, hex.EncodeToString(h[:]))
			}
			fields[fieldName] = hexValues
		}
		cfg.Measurements[platformName] = fields
	}

	data, _ := json.Marshal(cfg)
	return data
}
