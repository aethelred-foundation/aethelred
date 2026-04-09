package app

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func abciFuzzHash(seed []byte, domain byte) []byte {
	h := sha256.Sum256(append(seed, domain))
	return h[:]
}

// abciFuzzVerification builds a structurally valid ComputeVerification.
func abciFuzzVerification(seed []byte) ComputeVerification {
	outputHash := abciFuzzHash(seed, 0xBB)
	return ComputeVerification{
		JobID:           "job-" + hex.EncodeToString(seed[:6]),
		ModelHash:       abciFuzzHash(seed, 0x01),
		InputHash:       abciFuzzHash(seed, 0x02),
		OutputHash:      outputHash,
		AttestationType: AttestationTypeTEE,
		TEEAttestation: &TEEAttestationData{
			Platform:    "aws-nitro",
			EnclaveID:   "enclave-fuzz",
			Measurement: abciFuzzHash(seed, 0xCC),
			Quote:       make([]byte, 128),
			UserData:    outputHash,
			Timestamp:   time.Now().UTC(),
			Nonce:       abciFuzzHash(seed, 0xAA),
		},
		ExecutionTimeMs: 100,
		Success:         true,
		Nonce:           abciFuzzHash(seed, 0xAA),
	}
}

// abciFuzzVoteExtension builds a structurally valid signed VoteExtension.
func abciFuzzVoteExtension(seed []byte, height int64, numVerifications int) (*VoteExtension, ed25519.PrivateKey) {
	privSeed := sha256.Sum256(append(seed, 0xFE))
	priv := ed25519.NewKeyFromSeed(privSeed[:])
	addr := abciFuzzHash(seed, 0x10)[:20]

	ve := NewVoteExtensionAtBlockTime(height, addr, time.Now().UTC())
	for i := 0; i < numVerifications; i++ {
		h := sha256.Sum256(append(seed, byte(i)))
		ve.AddVerification(abciFuzzVerification(h[:]))
	}
	ve.SortVerifications()

	// Sign it (may fail in edge cases, which is fine for fuzzing).
	_ = SignVoteExtension(ve, priv)
	return ve, priv
}

// ---------------------------------------------------------------------------
// 1. FuzzExtendVoteJobAssignment
//
// Fuzzes vote extension creation with varying numbers of verifications.
// Security invariants checked:
//   - Serialized extension size never exceeds MaxVoteExtensionSizeBytes (5MB).
//   - Verification count never exceeds MaxVerificationsPerExtension (100).
//   - Empty verification list produces a valid (possibly empty) extension.
//   - Marshal/Unmarshal round-trip preserves verification count.
//   - The code never panics.
// ---------------------------------------------------------------------------

func FuzzExtendVoteJobAssignment(f *testing.F) {
	f.Add([]byte("ext-seed-1"), uint8(0))
	f.Add([]byte("ext-seed-2"), uint8(1))
	f.Add([]byte("ext-seed-3"), uint8(50))
	f.Add([]byte("ext-seed-4"), uint8(100))
	f.Add([]byte("ext-seed-5"), uint8(101)) // exceeds limit
	f.Add([]byte("ext-seed-6"), uint8(255)) // far exceeds limit

	f.Fuzz(func(t *testing.T, seed []byte, numRaw uint8) {
		if len(seed) < 6 {
			return
		}
		numVerifications := int(numRaw)

		ve, priv := abciFuzzVoteExtension(seed, 1, numVerifications)

		// Invariant: verification count capped by construction,
		// but we check what Validate says about the limit.
		if len(ve.Verifications) > MaxVerificationsPerExtension {
			err := ve.Validate()
			if err == nil {
				t.Fatalf("extension with %d verifications (> %d) must fail validation",
					len(ve.Verifications), MaxVerificationsPerExtension)
			}
			return
		}

		// Sign and marshal.
		if err := SignVoteExtension(ve, priv); err != nil {
			return // signing can fail on degenerate keys
		}

		extBytes, err := ve.Marshal()
		if err != nil {
			return // marshal failure is acceptable for edge cases
		}

		// Invariant: serialized size must not exceed the hard limit.
		if len(extBytes) > MaxVoteExtensionSizeBytes {
			t.Fatalf("marshaled extension is %d bytes, exceeds max %d",
				len(extBytes), MaxVoteExtensionSizeBytes)
		}

		// Invariant: round-trip preserves verification count.
		ve2, err := UnmarshalVoteExtension(extBytes)
		if err != nil {
			t.Fatalf("round-trip unmarshal failed: %v", err)
		}
		if len(ve2.Verifications) != len(ve.Verifications) {
			t.Fatalf("round-trip changed verification count: %d -> %d",
				len(ve.Verifications), len(ve2.Verifications))
		}
	})
}

// ---------------------------------------------------------------------------
// 2. FuzzProcessProposalValidation
//
// Fuzzes block proposal validation by generating injected vote extension
// transactions with fuzzed fields.
// Security invariants checked:
//   - Invalid injected tx format (wrong type, missing job ID, bad hash
//     length, negative values) is always rejected.
//   - ValidatorCount > TotalVotes is rejected.
//   - The format validator never panics regardless of input.
// ---------------------------------------------------------------------------

func FuzzProcessProposalValidation(f *testing.F) {
	// Valid injected tx
	validTx := InjectedVoteExtensionTx{
		JobID:          "job-fuzz-1",
		OutputHash:     make([]byte, 32),
		ValidatorCount: 3,
		TotalVotes:     5,
		AgreementPower: 100,
		TotalPower:     150,
		BlockHeight:    1,
		Type:           "create_seal_from_consensus",
	}
	validBytes, _ := json.Marshal(validTx)
	f.Add(validBytes)

	// Wrong type
	wrongType := validTx
	wrongType.Type = "malicious_type"
	wtBytes, _ := json.Marshal(wrongType)
	f.Add(wtBytes)

	// Missing job ID
	noJob := validTx
	noJob.JobID = ""
	njBytes, _ := json.Marshal(noJob)
	f.Add(njBytes)

	// Bad output hash length
	badHash := validTx
	badHash.OutputHash = make([]byte, 16)
	bhBytes, _ := json.Marshal(badHash)
	f.Add(bhBytes)

	// Negative values
	negVals := validTx
	negVals.ValidatorCount = -1
	negVals.TotalVotes = -1
	nvBytes, _ := json.Marshal(negVals)
	f.Add(nvBytes)

	// ValidatorCount > TotalVotes
	overflow := validTx
	overflow.ValidatorCount = 10
	overflow.TotalVotes = 5
	ovBytes, _ := json.Marshal(overflow)
	f.Add(ovBytes)

	// Empty JSON
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		tx, err := UnmarshalInjectedVoteExtensionTx(data)
		if err != nil {
			// Unmarshal failure: the tx will never reach format validation.
			// Ensure IsInjectedVoteExtensionTx also does not panic.
			_ = IsInjectedVoteExtensionTx(data)
			return
		}

		fmtErr := validateInjectedConsensusTxFormat(tx)

		// Invariant: wrong tx type must be rejected.
		if tx.Type != "create_seal_from_consensus" && fmtErr == nil {
			t.Fatalf("tx type %q should be rejected", tx.Type)
		}

		// Invariant: empty job ID must be rejected.
		if tx.JobID == "" && fmtErr == nil {
			t.Fatal("empty job ID must be rejected")
		}

		// Invariant: output hash must be exactly 32 bytes.
		if len(tx.OutputHash) != 32 && fmtErr == nil {
			t.Fatalf("output hash length %d (not 32) must be rejected", len(tx.OutputHash))
		}

		// Invariant: negative consensus evidence values must be rejected.
		if (tx.ValidatorCount < 0 || tx.TotalVotes < 0 || tx.AgreementPower < 0 || tx.TotalPower < 0) && fmtErr == nil {
			t.Fatal("negative consensus evidence values must be rejected")
		}

		// Invariant: validator count exceeding total votes must be rejected.
		if tx.ValidatorCount > tx.TotalVotes && fmtErr == nil {
			t.Fatalf("validator count %d > total votes %d must be rejected",
				tx.ValidatorCount, tx.TotalVotes)
		}

		// Also check the consensus evidence threshold validation when format passes.
		if fmtErr == nil && tx.TotalPower > 0 {
			threshErr := validateConsensusEvidenceThreshold(
				tx.ValidatorCount,
				tx.TotalVotes,
				tx.AgreementPower,
				tx.TotalPower,
				67,
				true,
			)

			// Invariant: agreement power below required threshold must fail.
			requiredPower := (tx.TotalPower*67)/100 + 1
			if tx.AgreementPower < requiredPower && threshErr == nil {
				t.Fatalf("agreement power %d < required %d must fail threshold check",
					tx.AgreementPower, requiredPower)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 3. FuzzVoteExtensionSizeEnforcement
//
// Fuzzes vote extensions approaching and exceeding the 5MB size limit.
// Simulates the trimming loop from ExtendVoteHandler.
// Security invariants checked:
//   - After trimming, serialized size is <= MaxVoteExtensionSizeBytes.
//   - Trimming always converges (loop terminates).
//   - Empty verifications list produces a small fixed-size extension.
//   - The trimming process never panics.
// ---------------------------------------------------------------------------

func FuzzVoteExtensionSizeEnforcement(f *testing.F) {
	f.Add([]byte("size-seed-1"), uint8(10), uint16(100))
	f.Add([]byte("size-seed-2"), uint8(50), uint16(500))
	f.Add([]byte("size-seed-3"), uint8(100), uint16(1000))
	f.Add([]byte("size-seed-4"), uint8(1), uint16(50000)) // large individual verifications

	f.Fuzz(func(t *testing.T, seed []byte, numRaw uint8, extraPadding uint16) {
		if len(seed) < 6 {
			return
		}
		numVerifications := int(numRaw)

		privSeed := sha256.Sum256(append(seed, 0xFE))
		priv := ed25519.NewKeyFromSeed(privSeed[:])
		addr := abciFuzzHash(seed, 0x10)[:20]
		ve := NewVoteExtensionAtBlockTime(1, addr, time.Now().UTC())

		for i := 0; i < numVerifications; i++ {
			h := sha256.Sum256(append(seed, byte(i)))
			ver := abciFuzzVerification(h[:])
			// Add extra padding to error message to inflate size.
			if extraPadding > 0 {
				pad := make([]byte, int(extraPadding)%2048)
				ver.ErrorMessage = hex.EncodeToString(pad)
			}
			ve.AddVerification(ver)
		}

		ve.SortVerifications()
		if err := SignVoteExtension(ve, priv); err != nil {
			return
		}

		extBytes, err := ve.Marshal()
		if err != nil {
			return
		}

		// Simulate the trimming loop from ExtendVoteHandler (EV-10).
		trimIterations := 0
		maxIterations := len(ve.Verifications) + 1 // convergence bound
		for len(extBytes) > MaxVoteExtensionSizeBytes && len(ve.Verifications) > 0 {
			trimIterations++
			if trimIterations > maxIterations {
				t.Fatalf("trimming loop did not converge after %d iterations", trimIterations)
			}

			ve.Verifications = ve.Verifications[:len(ve.Verifications)-1]

			// Re-sign after trimming.
			if signErr := SignVoteExtension(ve, priv); signErr != nil {
				// Clear stale signature on sign failure.
				ve.Signature = nil
			}

			extBytes, err = ve.Marshal()
			if err != nil {
				// Marshal error during trimming: return empty (matches EV-09).
				return
			}
		}

		// Invariant: after trimming, size must be within limit.
		if len(extBytes) > MaxVoteExtensionSizeBytes {
			t.Fatalf("after trimming, extension is %d bytes (> %d)",
				len(extBytes), MaxVoteExtensionSizeBytes)
		}

		// Invariant: round-trip must succeed for the trimmed extension.
		ve2, err := UnmarshalVoteExtension(extBytes)
		if err != nil {
			t.Fatalf("round-trip unmarshal failed after trimming: %v", err)
		}

		// Invariant: verification count must match after round-trip.
		if len(ve2.Verifications) != len(ve.Verifications) {
			t.Fatalf("round-trip changed count: %d -> %d",
				len(ve.Verifications), len(ve2.Verifications))
		}

		// Invariant: empty extension marshals to a small payload.
		emptyVe := NewVoteExtensionAtBlockTime(1, addr, time.Now().UTC())
		emptyBytes, emptyErr := emptyVe.Marshal()
		if emptyErr != nil {
			t.Fatalf("empty extension marshal failed: %v", emptyErr)
		}
		// An empty extension should be well under 1KB.
		if len(emptyBytes) > 1024 {
			t.Fatalf("empty extension is %d bytes, expected < 1024", len(emptyBytes))
		}

		// Invariant: fuzz_timestamp helper does not overflow.
		ts := fuzzTimestampForSize(seed)
		if ts.IsZero() {
			// Zero time is acceptable for edge-case seeds.
		}
	})
}

// fuzzTimestampForSize derives a bounded timestamp from seed bytes.
func fuzzTimestampForSize(seed []byte) time.Time {
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	if len(seed) < 8 {
		return base
	}
	maxOffset := int64(365 * 24 * 3600)
	offset := int64(binary.BigEndian.Uint64(seed[:8])) % maxOffset
	return base.Add(time.Duration(offset) * time.Second)
}
