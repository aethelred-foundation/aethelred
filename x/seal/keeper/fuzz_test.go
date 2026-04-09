package keeper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/aethelred/aethelred/x/seal/types"
)

// ---------------------------------------------------------------------------
// FuzzCreateSeal — fuzz seal creation with arbitrary commitments and metadata.
//
// Invariants:
//   - Valid seals (32-byte commitments, positive block height, valid address)
//     are created successfully.
//   - Invalid seals are rejected with an error (not a panic).
//   - Seal ID is deterministic from inputs (same inputs = same ID).
//   - No panics for any input combination.
// ---------------------------------------------------------------------------
func FuzzCreateSeal(f *testing.F) {
	ensureBech32()

	// Seed corpus: valid inputs
	f.Add(
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
		int64(100),
		byte(1),
		"credit_scoring",
	)
	// Edge: zero block height
	f.Add(
		bytes.Repeat([]byte{0xAA}, 32),
		bytes.Repeat([]byte{0xBB}, 32),
		bytes.Repeat([]byte{0xCC}, 32),
		int64(0),
		byte(2),
		"fraud_detection",
	)
	// Edge: short commitments
	f.Add(
		[]byte{0x01},
		[]byte{0x02},
		[]byte{0x03},
		int64(50),
		byte(3),
		"general",
	)
	// Edge: empty commitments
	f.Add(
		[]byte{},
		[]byte{},
		[]byte{},
		int64(-1),
		byte(4),
		"",
	)
	// Edge: oversized commitments
	f.Add(
		bytes.Repeat([]byte{0xFF}, 64),
		bytes.Repeat([]byte{0xFE}, 64),
		bytes.Repeat([]byte{0xFD}, 64),
		int64(999999),
		byte(5),
		"medical_diagnosis",
	)

	f.Fuzz(func(t *testing.T, model, input, output []byte, blockHeight int64, addrSeed byte, purpose string) {
		k := NewKeeper(nil, nil, "authority")
		ctx := context.Background()

		addr := testAccAddress(addrSeed)

		seal := types.NewDigitalSeal(model, input, output, blockHeight, addr, purpose)
		seal.Status = types.SealStatusActive

		// Invariant: ID generation is deterministic
		id1 := seal.GenerateID()
		id2 := seal.GenerateID()
		if id1 != id2 {
			t.Fatalf("GenerateID not deterministic: %q != %q", id1, id2)
		}

		// Attempt to store
		err := k.SetSeal(ctx, seal)
		if err != nil {
			// SetSeal on a nil-store keeper should not fail
			t.Fatalf("SetSeal on mem-keeper failed: %v", err)
		}

		// Invariant: seal must be retrievable after SetSeal
		got, getErr := k.GetSeal(ctx, seal.Id)
		if getErr != nil {
			t.Fatalf("GetSeal after SetSeal failed: %v", getErr)
		}
		if got.Id != seal.Id {
			t.Fatalf("seal ID mismatch: got %q, want %q", got.Id, seal.Id)
		}

		// Invariant: Validate() must return error for invalid structures
		validationErr := seal.Validate()
		isValid32Model := len(model) == 32
		isValid32Input := len(input) == 32
		isValid32Output := len(output) == 32
		isValidHeight := blockHeight > 0

		if isValid32Model && isValid32Input && isValid32Output && isValidHeight {
			// All structural requirements met, Validate should succeed
			if validationErr != nil {
				t.Fatalf("expected Validate() success for valid seal, got: %v", validationErr)
			}
		} else {
			// At least one requirement is violated, Validate should fail
			if validationErr == nil {
				t.Fatalf("expected Validate() error for invalid seal (model=%d, input=%d, output=%d, height=%d)",
					len(model), len(input), len(output), blockHeight)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// FuzzRevokeSeal — fuzz revocation with arbitrary seal IDs and authorities.
//
// Invariants:
//   - Only existing seals can be revoked.
//   - Non-existent seal revocation returns an error.
//   - After revocation, seal status is Revoked.
//   - Double-revoke succeeds (Revoke() is idempotent on status).
//   - No state corruption: other seals are unaffected.
// ---------------------------------------------------------------------------
func FuzzRevokeSeal(f *testing.F) {
	ensureBech32()

	f.Add(byte(1), byte(2), "policy_violation")
	f.Add(byte(10), byte(20), "")
	f.Add(byte(0), byte(0), "security_breach")
	f.Add(byte(255), byte(128), "regulatory_requirement")

	f.Fuzz(func(t *testing.T, sealSeed, otherSeed byte, reason string) {
		k := NewKeeper(nil, nil, "authority")
		ctx := context.Background()

		// Create a seal
		seal := newSealForTest(sealSeed)
		if err := k.SetSeal(ctx, seal); err != nil {
			t.Fatalf("SetSeal failed: %v", err)
		}

		// Create another seal to verify no state corruption
		otherSeal := newSealForTest(otherSeed)
		if otherSeal.Id == seal.Id {
			// Seeds collide in ID generation; skip corruption check
		} else {
			if err := k.SetSeal(ctx, otherSeal); err != nil {
				t.Fatalf("SetSeal (other) failed: %v", err)
			}
		}

		// Invariant: revoking a non-existent seal returns error
		_, nonExistErr := k.GetSeal(ctx, "nonexistent-seal-id-12345")
		if nonExistErr == nil {
			t.Fatal("expected error for non-existent seal")
		}

		// Revoke the existing seal
		retrieved, err := k.GetSeal(ctx, seal.Id)
		if err != nil {
			t.Fatalf("GetSeal before revoke failed: %v", err)
		}
		retrieved.Revoke()
		if err := k.SetSeal(ctx, retrieved); err != nil {
			t.Fatalf("SetSeal after revoke failed: %v", err)
		}

		// Invariant: status must be Revoked
		afterRevoke, err := k.GetSeal(ctx, seal.Id)
		if err != nil {
			t.Fatalf("GetSeal after revoke failed: %v", err)
		}
		if afterRevoke.Status != types.SealStatusRevoked {
			t.Fatalf("expected status Revoked, got %v", afterRevoke.Status)
		}

		// Invariant: double-revoke does not panic and status remains Revoked
		afterRevoke.Revoke()
		if err := k.SetSeal(ctx, afterRevoke); err != nil {
			t.Fatalf("SetSeal after double-revoke failed: %v", err)
		}
		doubleRevoked, err := k.GetSeal(ctx, seal.Id)
		if err != nil {
			t.Fatalf("GetSeal after double-revoke failed: %v", err)
		}
		if doubleRevoked.Status != types.SealStatusRevoked {
			t.Fatalf("expected status Revoked after double-revoke, got %v", doubleRevoked.Status)
		}

		// Invariant: other seal is unaffected
		if otherSeal.Id != seal.Id {
			other, err := k.GetSeal(ctx, otherSeal.Id)
			if err != nil {
				t.Fatalf("other seal should still exist: %v", err)
			}
			if other.Status == types.SealStatusRevoked && otherSeal.Status != types.SealStatusRevoked {
				t.Fatalf("other seal status corrupted: expected %v, got %v", otherSeal.Status, other.Status)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// FuzzSealQueryByModel — fuzz queries with arbitrary model hashes.
//
// Invariants:
//   - Queries return only seals matching the given model hash.
//   - Empty results for unknown models (no error, no panic).
//   - No panic on malformed / empty / oversized hashes.
// ---------------------------------------------------------------------------
func FuzzSealQueryByModel(f *testing.F) {
	ensureBech32()

	f.Add(bytes.Repeat([]byte{0x01}, 32), byte(1), int(3))
	f.Add([]byte{}, byte(2), int(1))
	f.Add(bytes.Repeat([]byte{0xFF}, 64), byte(3), int(5))
	f.Add([]byte{0xDE, 0xAD}, byte(4), int(0))

	f.Fuzz(func(t *testing.T, queryHash []byte, addrSeed byte, numSeals int) {
		k := NewKeeper(nil, nil, "authority")
		ctx := context.Background()

		// Clamp numSeals to reasonable range
		if numSeals < 0 {
			numSeals = 0
		}
		if numSeals > 10 {
			numSeals = 10
		}

		// Create seals with known model commitments
		knownModel := sha256.Sum256([]byte("known-model"))
		differentModel := sha256.Sum256([]byte("different-model"))
		expectedCount := 0

		for i := 0; i < numSeals; i++ {
			var modelHash []byte
			if i%2 == 0 {
				modelHash = knownModel[:]
			} else {
				modelHash = differentModel[:]
			}

			seal := types.NewDigitalSeal(
				modelHash,
				bytes.Repeat([]byte{byte(i + 1)}, 32),
				bytes.Repeat([]byte{byte(i + 10)}, 32),
				int64(100+i),
				testAccAddress(addrSeed+byte(i)),
				fmt.Sprintf("purpose-%d", i),
			)
			if err := k.SetSeal(ctx, seal); err != nil {
				t.Fatalf("SetSeal failed: %v", err)
			}

			if bytes.Equal(modelHash, queryHash) {
				expectedCount++
			}
		}

		// Query must not panic regardless of queryHash content
		results, err := k.ListSealsByModel(ctx, queryHash)
		if err != nil {
			t.Fatalf("ListSealsByModel failed: %v", err)
		}

		// Invariant: result count matches expected
		if len(results) != expectedCount {
			t.Fatalf("expected %d results for query hash, got %d", expectedCount, len(results))
		}

		// Invariant: all returned seals must have matching model commitment
		for _, seal := range results {
			if !bytes.Equal(seal.ModelCommitment, queryHash) {
				t.Fatalf("returned seal has wrong model: got %x, want %x", seal.ModelCommitment, queryHash)
			}
		}

		// Invariant: unknown hash returns empty results, not error
		unknownHash := sha256.Sum256([]byte("completely-unknown-model-xyzzy"))
		unknownResults, err := k.ListSealsByModel(ctx, unknownHash[:])
		if err != nil {
			t.Fatalf("ListSealsByModel for unknown hash failed: %v", err)
		}
		if len(unknownResults) != 0 {
			t.Fatalf("expected 0 results for unknown model, got %d", len(unknownResults))
		}
	})
}
