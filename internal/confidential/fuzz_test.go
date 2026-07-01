package confidential

import (
	"testing"
)

// FuzzSafeUnmarshalCiphertext asserts the no-panic invariant on the FHE
// worker's untrusted-input surface: EncryptedInput arrives from the network,
// and lattigo's UnmarshalBinary panics on malformed bytes — the recover guard
// must convert EVERY such input into an error, never a crash.
func FuzzSafeUnmarshalCiphertext(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte("not-a-ciphertext"))
	f.Add(make([]byte, 512))

	// A genuine ciphertext as a structured seed for mutation.
	client, err := NewFHEClient(4)
	if err != nil {
		f.Fatal(err)
	}
	ct, err := client.Encrypt([]float64{1, 2, 3})
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(ct))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("safeUnmarshalCiphertext panicked: %v", r)
			}
		}()
		_, _ = safeUnmarshalCiphertext(data)
	})
}

// FuzzUnmarshalShareBundle asserts the no-panic invariant on the MPC worker's
// untrusted-input surface, including hostile shape headers (huge n/dim).
func FuzzUnmarshalShareBundle(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 1})
	// Hostile shape: header claims 1024 parties × 2^20 dims.
	f.Add([]byte{0, 0, 0, 1, 0, 0, 4, 0, 0, 16, 0, 0})

	shares, err := SplitShares([]float64{1.5, -2}, 3)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(marshalShareBundle(shares))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("unmarshalShareBundle panicked: %v", r)
			}
		}()
		if shares, err := unmarshalShareBundle(data); err == nil {
			// Accepted bundles must be internally consistent (no oversized
			// allocations smuggled past the shape check).
			if len(shares) < 2 || len(shares) > 1024 {
				t.Fatalf("accepted bundle with implausible party count %d", len(shares))
			}
		}
	})
}

// FuzzReadCiphertextFrames asserts the no-panic invariant on the FHE client's
// result-parsing surface (frames come back from an untrusted worker).
func FuzzReadCiphertextFrames(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0})
	f.Add([]byte{0, 0, 0, 9, 1, 2})
	f.Add(appendFrame(nil, []byte("garbage")))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("readCiphertextFrames panicked: %v", r)
			}
		}()
		_, _ = readCiphertextFrames(data, nil)
	})
}
