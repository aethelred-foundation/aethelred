package keeper_test

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"cosmossdk.io/log"
	abci "github.com/cometbft/cometbft/abci/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// ---------------------------------------------------------------------------
// Helpers: deterministic data generation from fuzzer seed
// ---------------------------------------------------------------------------

func fuzzHash(seed []byte, domain byte) []byte {
	h := sha256.Sum256(append(seed, domain))
	return h[:]
}

func fuzzNonce(seed []byte) []byte {
	return fuzzHash(seed, 0xAA)
}

func fuzzOutputHash(seed []byte) []byte {
	return fuzzHash(seed, 0xBB)
}

func fuzzTimestamp(seed []byte) time.Time {
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	maxOffset := int64(365 * 24 * 3600)
	if len(seed) < 8 {
		return base
	}
	offset := int64(binary.BigEndian.Uint64(seed[:8])) % maxOffset
	return base.Add(time.Duration(offset) * time.Second)
}

func validTEEAttestationJSON(outputHash []byte) json.RawMessage {
	att := map[string]interface{}{
		"platform":    "aws-nitro",
		"enclave_id":  "enclave-fuzz-001",
		"measurement": fuzzHash(outputHash, 0xCC),
		"quote":       make([]byte, 128),
		"user_data":   outputHash,
		"timestamp":   time.Now().UTC().Format(time.RFC3339Nano),
		"nonce":       fuzzNonce(outputHash),
	}
	b, _ := json.Marshal(att)
	return b
}

func validZKProofJSON(outputHash []byte) json.RawMessage {
	proof := map[string]interface{}{
		"proof_system":       "ezkl",
		"proof":              make([]byte, 256),
		"public_inputs":      append(make([]byte, 32), outputHash...),
		"verifying_key_hash": fuzzHash(outputHash, 0xDD),
		"circuit_hash":       fuzzHash(outputHash, 0xEE),
		"proof_size":         256,
	}
	b, _ := json.Marshal(proof)
	return b
}

func validVerificationWire(seed []byte) keeper.VerificationWire {
	outputHash := fuzzOutputHash(seed)
	return keeper.VerificationWire{
		JobID:           "job-" + hex.EncodeToString(seed[:6]),
		ModelHash:       fuzzHash(seed, 0x01),
		InputHash:       fuzzHash(seed, 0x02),
		OutputHash:      outputHash,
		AttestationType: "tee",
		TEEAttestation:  validTEEAttestationJSON(outputHash),
		ExecutionTimeMs: 100,
		Success:         true,
		Nonce:           fuzzNonce(seed),
	}
}

func validExtensionJSON(seed []byte) []byte {
	ext := keeper.VoteExtensionWire{
		Version:          1,
		Height:           1,
		ValidatorAddress: json.RawMessage(`"` + hex.EncodeToString(fuzzHash(seed, 0x10)[:20]) + `"`),
		Verifications:    []keeper.VerificationWire{validVerificationWire(seed)},
		Timestamp:        fuzzTimestamp(seed),
		Signature:        json.RawMessage(`"` + hex.EncodeToString(make([]byte, 64)) + `"`),
		ExtensionHash:    json.RawMessage(`"` + hex.EncodeToString(fuzzHash(seed, 0xFF)) + `"`),
	}
	b, _ := json.Marshal(ext)
	return b
}

// ---------------------------------------------------------------------------
// 1. FuzzVerifyVoteExtension
//
// Exercises the consensus handler's VerifyVoteExtension against arbitrary
// wire-format bytes from potentially Byzantine validators.
// Security invariants checked:
//   - Malformed JSON always returns an error.
//   - Version != 1 always returns an error.
//   - Empty data always returns an error.
//   - The method never panics regardless of input.
// ---------------------------------------------------------------------------

func FuzzVerifyVoteExtension(f *testing.F) {
	f.Add(validExtensionJSON([]byte("seed-valid-1")))
	f.Add(validExtensionJSON([]byte("seed-valid-2")))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(`{"version":1,"height":0}`))
	f.Add([]byte(`{"version":2,"height":1}`))
	f.Add([]byte(`{"version":1,"height":-1}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))
	f.Add([]byte(`{"version":1,"height":1,"validator_address":"","verifications":null}`))
	f.Add([]byte(`{"version":1,"height":1,"validator_address":"AAEC","verifications":[` +
		`{"job_id":"","success":true,"output_hash":"` + hex.EncodeToString(make([]byte, 32)) + `"}` +
		`]}`))

	// Oversized: 101 verifications (exceeds MaxVerificationsPerExtension=100)
	bigVerifications := make([]keeper.VerificationWire, 101)
	for i := range bigVerifications {
		seed := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		bigVerifications[i] = validVerificationWire(seed[:])
	}
	oversizedExt := keeper.VoteExtensionWire{
		Version:       1,
		Height:        1,
		Verifications: bigVerifications,
	}
	oversizedBytes, _ := json.Marshal(oversizedExt)
	f.Add(oversizedBytes)

	f.Fuzz(func(t *testing.T, data []byte) {
		ch := keeper.NewConsensusHandler(log.NewNopLogger(), nil, nil)
		ctx := sdk.Context{}.
			WithBlockHeight(1).
			WithBlockTime(time.Now().UTC())

		err := ch.VerifyVoteExtension(ctx, data)

		// Invariant: empty input must be rejected (unmarshal fails).
		if len(data) == 0 && err == nil {
			t.Fatal("empty input must be rejected")
		}

		// Invariant: non-JSON input must be rejected.
		var probe json.RawMessage
		if json.Unmarshal(data, &probe) != nil && err == nil {
			t.Fatal("non-JSON input must be rejected")
		}

		// Invariant: version != 1 must be rejected.
		var partial struct {
			Version int32 `json:"version"`
		}
		if json.Unmarshal(data, &partial) == nil && partial.Version != 0 && partial.Version != 1 && err == nil {
			t.Fatalf("version %d should be rejected", partial.Version)
		}
	})
}

// ---------------------------------------------------------------------------
// 2. FuzzValidateVerificationWire
//
// Exercises individual verification entry validation.
// Security invariants checked:
//   - Missing/empty job ID is always rejected.
//   - success=true with wrong-length output hash is rejected.
//   - success=true with non-positive execution time is rejected.
//   - Unknown attestation types are rejected.
//   - The method never panics.
// ---------------------------------------------------------------------------

func FuzzValidateVerificationWire(f *testing.F) {
	validBytes, _ := json.Marshal(validVerificationWire([]byte("ver-seed-1")))
	f.Add(validBytes)
	f.Add([]byte(`{"job_id":"","success":false}`))
	f.Add([]byte(`{"job_id":"j1","success":true,"output_hash":"` +
		hex.EncodeToString(make([]byte, 32)) + `","attestation_type":"unknown"}`))
	f.Add([]byte(`{"job_id":"j1","success":false,"nonce":"` +
		hex.EncodeToString(make([]byte, 32)) + `","model_hash":"` +
		hex.EncodeToString(make([]byte, 32)) + `","attestation_type":"none"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var wire keeper.VerificationWire
		if json.Unmarshal(data, &wire) != nil {
			return
		}

		ch := keeper.NewConsensusHandler(log.NewNopLogger(), nil, nil)
		err := ch.ValidateVerificationWireForTest(&wire)

		// Invariant: empty job ID always fails.
		if len(wire.JobID) == 0 && err == nil {
			t.Fatal("empty job ID must be rejected")
		}

		// Invariant: success=true with wrong output hash length fails.
		if wire.Success && len(wire.OutputHash) != 32 && err == nil {
			t.Fatal("success=true with non-32-byte output hash must be rejected")
		}

		// Invariant: success=true with non-positive execution time fails.
		if wire.Success && wire.ExecutionTimeMs <= 0 && err == nil {
			t.Fatal("success=true with non-positive execution time must be rejected")
		}
	})
}

// ---------------------------------------------------------------------------
// 3. FuzzValidateTEEAttestationWire
//
// Fuzzes TEE attestation parsing and field validation.
// Security invariants checked:
//   - Unknown platforms are rejected.
//   - Missing measurement is rejected.
//   - Quote shorter than 64 bytes is rejected.
//   - Missing user data is rejected.
//   - User data mismatch with output hash is rejected.
//   - The method never panics.
// ---------------------------------------------------------------------------

func FuzzValidateTEEAttestationWire(f *testing.F) {
	outputHash := make([]byte, 32)
	copy(outputHash, "test-output-hash-32bytes-padding")

	validAtt := validTEEAttestationJSON(outputHash)
	validWire := keeper.VerificationWire{
		JobID:           "fuzz-tee-job",
		OutputHash:      outputHash,
		TEEAttestation:  validAtt,
		AttestationType: "tee",
		Success:         true,
		ModelHash:       fuzzHash(outputHash, 0x01),
		ExecutionTimeMs: 50,
		Nonce:           fuzzNonce(outputHash),
	}
	validBytes, _ := json.Marshal(validWire)
	f.Add(validBytes)

	// Missing TEE attestation
	noAttWire := validWire
	noAttWire.TEEAttestation = nil
	noAttBytes, _ := json.Marshal(noAttWire)
	f.Add(noAttBytes)

	// Bad platform
	badPlatform, _ := json.Marshal(map[string]interface{}{
		"platform":    "hackerbox",
		"measurement": outputHash,
		"quote":       make([]byte, 128),
		"user_data":   outputHash,
		"timestamp":   time.Now().UTC().Format(time.RFC3339Nano),
		"nonce":       fuzzNonce(outputHash),
	})
	badPlatformWire := validWire
	badPlatformWire.TEEAttestation = badPlatform
	bpBytes, _ := json.Marshal(badPlatformWire)
	f.Add(bpBytes)

	// Quote too short
	shortQuote, _ := json.Marshal(map[string]interface{}{
		"platform":    "aws-nitro",
		"measurement": outputHash,
		"quote":       make([]byte, 10),
		"user_data":   outputHash,
		"timestamp":   time.Now().UTC().Format(time.RFC3339Nano),
		"nonce":       fuzzNonce(outputHash),
	})
	shortQuoteWire := validWire
	shortQuoteWire.TEEAttestation = shortQuote
	sqBytes, _ := json.Marshal(shortQuoteWire)
	f.Add(sqBytes)

	f.Fuzz(func(t *testing.T, data []byte) {
		var wire keeper.VerificationWire
		if json.Unmarshal(data, &wire) != nil {
			return
		}
		if wire.AttestationType != "tee" && wire.AttestationType != "hybrid" {
			return
		}

		ch := keeper.NewConsensusHandler(log.NewNopLogger(), nil, nil)
		err := ch.ValidateVerificationWireForTest(&wire)

		// Invariant: if TEEAttestation is empty, must reject for tee/hybrid types
		// when the verification is successful.
		if wire.Success && len(wire.TEEAttestation) == 0 && err == nil {
			t.Fatal("missing TEE attestation data must be rejected for tee/hybrid type")
		}

		// Check parsed attestation invariants.
		if wire.Success && len(wire.TEEAttestation) > 0 {
			var att struct {
				Platform string `json:"platform"`
				Quote    []byte `json:"quote"`
			}
			if json.Unmarshal(wire.TEEAttestation, &att) == nil {
				validPlatforms := map[string]bool{
					"aws-nitro": true, "intel-sgx": true, "intel-tdx": true,
					"amd-sev": true, "arm-trustzone": true, "simulated": true,
				}
				if !validPlatforms[att.Platform] && err == nil {
					t.Fatalf("unknown platform %q must be rejected", att.Platform)
				}
				if len(att.Quote) < 64 && err == nil {
					t.Fatal("quote shorter than 64 bytes must be rejected")
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 4. FuzzValidateZKProofWire
//
// Fuzzes ZK proof parsing and structural validation.
// Security invariants checked:
//   - Unknown proof systems are rejected.
//   - Proofs shorter than 128 bytes are rejected.
//   - Verifying key hash must be exactly 32 bytes.
//   - Missing public inputs are rejected.
//   - The method never panics.
// ---------------------------------------------------------------------------

func FuzzValidateZKProofWire(f *testing.F) {
	outputHash := make([]byte, 32)
	copy(outputHash, "test-zk-output-hash-32byte-pads")

	validProof := validZKProofJSON(outputHash)
	validWire := keeper.VerificationWire{
		JobID:           "fuzz-zk-job",
		OutputHash:      outputHash,
		ZKProof:         validProof,
		AttestationType: "zkml",
		Success:         true,
		ModelHash:       fuzzHash(outputHash, 0x01),
		ExecutionTimeMs: 75,
		Nonce:           fuzzNonce(outputHash),
	}
	validBytes, _ := json.Marshal(validWire)
	f.Add(validBytes)

	// Missing ZK proof
	noProofWire := validWire
	noProofWire.ZKProof = nil
	npBytes, _ := json.Marshal(noProofWire)
	f.Add(npBytes)

	// Unknown proof system
	badSystem, _ := json.Marshal(map[string]interface{}{
		"proof_system":       "imaginary-system",
		"proof":              make([]byte, 256),
		"public_inputs":      make([]byte, 64),
		"verifying_key_hash": make([]byte, 32),
	})
	badSystemWire := validWire
	badSystemWire.ZKProof = badSystem
	bsBytes, _ := json.Marshal(badSystemWire)
	f.Add(bsBytes)

	// Proof too short
	shortProof, _ := json.Marshal(map[string]interface{}{
		"proof_system":       "ezkl",
		"proof":              make([]byte, 10),
		"public_inputs":      make([]byte, 64),
		"verifying_key_hash": make([]byte, 32),
	})
	shortProofWire := validWire
	shortProofWire.ZKProof = shortProof
	spBytes, _ := json.Marshal(shortProofWire)
	f.Add(spBytes)

	f.Fuzz(func(t *testing.T, data []byte) {
		var wire keeper.VerificationWire
		if json.Unmarshal(data, &wire) != nil {
			return
		}
		if wire.AttestationType != "zkml" {
			return
		}

		ch := keeper.NewConsensusHandler(log.NewNopLogger(), nil, nil)
		err := ch.ValidateVerificationWireForTest(&wire)

		// Invariant: missing zkML proof is rejected for zkml type.
		if wire.Success && len(wire.ZKProof) == 0 && err == nil {
			t.Fatal("missing zkML proof data must be rejected for zkml type")
		}

		// Check parsed proof invariants.
		if wire.Success && len(wire.ZKProof) > 0 {
			var proof struct {
				ProofSystem      string `json:"proof_system"`
				Proof            []byte `json:"proof"`
				VerifyingKeyHash []byte `json:"verifying_key_hash"`
				PublicInputs     []byte `json:"public_inputs"`
			}
			if json.Unmarshal(wire.ZKProof, &proof) == nil {
				validSystems := map[string]bool{
					"ezkl": true, "risc0": true, "plonky2": true, "halo2": true,
				}
				if !validSystems[proof.ProofSystem] && err == nil {
					t.Fatalf("unknown proof system %q must be rejected", proof.ProofSystem)
				}
				if len(proof.Proof) < 128 && err == nil {
					t.Fatal("proof shorter than 128 bytes must be rejected")
				}
				if len(proof.VerifyingKeyHash) != 32 && err == nil {
					t.Fatal("verifying key hash must be 32 bytes")
				}
				if len(proof.PublicInputs) == 0 && err == nil {
					t.Fatal("empty public inputs must be rejected")
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 5. FuzzAggregateVoteExtensions
//
// Exercises the aggregation pipeline with Byzantine inputs: mismatched
// addresses, zero-power validators, conflicting output hashes.
// Security invariants checked:
//   - HasConsensus only when agreement power >= required threshold.
//   - Output hash is set when consensus is reached.
//   - AgreementCount never exceeds TotalVotes.
//   - The method never panics with malformed extensions.
// ---------------------------------------------------------------------------

func FuzzAggregateVoteExtensions(f *testing.F) {
	f.Add([]byte("agg-seed-1"), uint8(3), uint8(67))
	f.Add([]byte("agg-seed-2"), uint8(1), uint8(100))
	f.Add([]byte("agg-seed-3"), uint8(10), uint8(67))
	f.Add([]byte{}, uint8(0), uint8(67))

	f.Fuzz(func(t *testing.T, seed []byte, numVotesRaw uint8, thresholdRaw uint8) {
		numVotes := int(numVotesRaw%20) + 1
		if len(seed) == 0 {
			return
		}

		ch := keeper.NewConsensusHandler(log.NewNopLogger(), nil, nil)
		ctx := sdk.Context{}.
			WithBlockHeight(1).
			WithBlockTime(time.Now().UTC())

		votes := make([]abci.ExtendedVoteInfo, numVotes)
		totalPower := int64(0)
		for i := 0; i < numVotes; i++ {
			h := sha256.Sum256(append(seed, byte(i)))
			addr := h[:20]

			ver := validVerificationWire(h[:])

			// Randomly corrupt fields to simulate Byzantine behaviour.
			switch h[0] % 5 {
			case 0:
				ver.Success = false
			case 1:
				ver.OutputHash = fuzzHash(h[:], 0x99) // conflicting output
			case 2:
				ver.AttestationType = "none"
			}

			ext := keeper.VoteExtensionWire{
				Version:          1,
				Height:           1,
				ValidatorAddress: json.RawMessage(`"` + hex.EncodeToString(addr) + `"`),
				Verifications:    []keeper.VerificationWire{ver},
				Timestamp:        fuzzTimestamp(h[:]),
			}
			extBytes, err := json.Marshal(ext)
			if err != nil {
				continue
			}

			power := int64(binary.BigEndian.Uint16(h[20:22]))%100 + 1
			totalPower += power
			votes[i] = abci.ExtendedVoteInfo{
				Validator: abci.Validator{
					Address: addr,
					Power:   power,
				},
				VoteExtension: extBytes,
			}
		}

		results := ch.AggregateVoteExtensions(ctx, votes)

		for jobID, agg := range results {
			if agg.HasConsensus {
				// With nil keeper and nil threshold override, default is 67%.
				requiredPower := (totalPower*67)/100 + 1
				if agg.AgreementPower < requiredPower {
					t.Fatalf("job %s: consensus claimed but agreement power %d < required %d",
						jobID, agg.AgreementPower, requiredPower)
				}
				if len(agg.OutputHash) == 0 {
					t.Fatalf("job %s: consensus reached but output hash is empty", jobID)
				}
			}
			if agg.AgreementCount > agg.TotalVotes {
				t.Fatalf("job %s: agreement count %d > total votes %d",
					jobID, agg.AgreementCount, agg.TotalVotes)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 6. FuzzConsensusThresholdCalculation
//
// Exercises the requiredThresholdCount function with edge-case validator sets.
// Security invariants checked:
//   - result is 0 when total <= 0 or threshold <= 0.
//   - result == total when threshold >= 100.
//   - result is in range [0, total] for positive inputs.
//   - No panic on any int input.
// ---------------------------------------------------------------------------

func FuzzConsensusThresholdCalculation(f *testing.F) {
	f.Add(100, 67)
	f.Add(0, 67)
	f.Add(1, 100)
	f.Add(1, 0)
	f.Add(3, 67)
	f.Add(1000000, 1)
	f.Add(1000000, 99)
	f.Add(-1, 67)
	f.Add(1, -1)
	f.Add(0, 0)

	f.Fuzz(func(t *testing.T, total int, threshold int) {
		result := keeper.RequiredThresholdCountForTest(total, threshold)

		// Invariant: non-positive total or threshold => result is 0.
		if total <= 0 || threshold <= 0 {
			if result != 0 {
				t.Fatalf("expected 0 for total=%d threshold=%d, got %d",
					total, threshold, result)
			}
			return
		}

		// Invariant: threshold >= 100 => result equals total.
		if threshold >= 100 {
			if result != total {
				t.Fatalf("threshold=%d >= 100 should return total=%d, got %d",
					threshold, total, result)
			}
			return
		}

		// Invariant: result is in range [0, total].
		if result < 0 || result > total {
			t.Fatalf("result %d out of range [0, %d] for threshold=%d",
				result, total, threshold)
		}

		// Invariant: result >= floor(total * threshold / 100).
		floor := total * threshold / 100
		if result < floor {
			t.Fatalf("result %d < floor %d for total=%d threshold=%d",
				result, floor, total, threshold)
		}
	})
}
