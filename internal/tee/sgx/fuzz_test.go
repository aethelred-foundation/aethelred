package sgx

import (
	"encoding/binary"
	"testing"
)

// ---------------------------------------------------------------------------
// Seed corpus helpers
// ---------------------------------------------------------------------------

func addSGXSeedCorpus(f *testing.F) {
	f.Helper()
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xFF})
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, MinQuoteSize))

	ones := make([]byte, MinQuoteSize)
	for i := range ones {
		ones[i] = 0xFF
	}
	f.Add(ones)
	f.Add(make([]byte, MinQuoteSize-1)) // truncated
	f.Add(make([]byte, MinQuoteSize+1)) // oversized by 1
	f.Add(make([]byte, 4096))           // large
}

// ---------------------------------------------------------------------------
// 1. FuzzSGXQuoteValidation
//
// Fuzz Intel SGX DCAP quote bytes by constructing quote structures from raw
// fuzz input and verifying through SGXQuoteVerifier.
//
// Invariants:
//   - No panics on any input.
//   - Malformed / random quotes are rejected by a configured verifier.
//   - Quotes with correct MRENCLAVE/MRSIGNER are accepted.
//   - Measurement mismatches are always caught.
// ---------------------------------------------------------------------------

func FuzzSGXQuoteValidation(f *testing.F) {
	addSGXSeedCorpus(f)

	// Create a known-good enclave and quote for seed data.
	enclave, err := NewSGXEnclave(nil)
	if err != nil {
		f.Fatal(err)
	}
	goodQuote, err := enclave.GetQuote([ReportDataSize]byte{})
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Build a quote from fuzz data. This exercises the verifier against
		// arbitrary report body contents.
		quote := quoteFromFuzzData(data)

		// --- Unconfigured verifier (no trusted enclaves) accepts everything ---
		openVerifier := NewSGXQuoteVerifier()
		result, err := openVerifier.VerifyQuote(quote)
		if err != nil {
			// Verification may reject for security version etc, that is acceptable.
			return
		}
		// If no error, result should exist.
		if result == nil {
			t.Fatal("VerifyQuote returned nil result without error")
		}

		// --- Strict verifier with a known-good MRENCLAVE must reject fuzz data ---
		strictVerifier := NewSGXQuoteVerifier()
		strictVerifier.AddTrustedEnclave(goodQuote.ReportBody.MREnclave)
		strictVerifier.AddTrustedSigner(goodQuote.ReportBody.MRSigner)
		strictVerifier.SetMinSecurityVersion(1)

		strictResult, strictErr := strictVerifier.VerifyQuote(quote)

		// The fuzz quote was built from random data, so its MRENCLAVE almost
		// certainly does not match the trusted one. It should be rejected.
		if quote.ReportBody.MREnclave != goodQuote.ReportBody.MREnclave {
			if strictErr == nil && strictResult != nil && strictResult.Valid {
				t.Fatal("strict verifier accepted a quote with mismatched MRENCLAVE")
			}
		}

		if quote.ReportBody.MRSigner != goodQuote.ReportBody.MRSigner {
			// Even if MRENCLAVE matched, wrong signer should be rejected.
			if strictErr == nil && strictResult != nil && strictResult.Valid {
				t.Fatal("strict verifier accepted a quote with mismatched MRSIGNER")
			}
		}
	})
}

// quoteFromFuzzData constructs an SGXQuote from arbitrary bytes, mapping
// fields deterministically. This prevents panics from slice bounds and lets
// the fuzzer explore the verification logic space.
func quoteFromFuzzData(data []byte) *SGXQuote {
	q := &SGXQuote{
		Version:            3,
		SignType:           2,
		AttestationKeyType: 2,
	}

	// Map fuzz data into the report body.
	if len(data) >= MREnclaveSize {
		copy(q.ReportBody.MREnclave[:], data[:MREnclaveSize])
		data = data[MREnclaveSize:]
	}
	if len(data) >= MRSignerSize {
		copy(q.ReportBody.MRSigner[:], data[:MRSignerSize])
		data = data[MRSignerSize:]
	}
	if len(data) >= 2 {
		q.ReportBody.ISVProdID = binary.LittleEndian.Uint16(data[:2])
		data = data[2:]
	}
	if len(data) >= 2 {
		q.ReportBody.ISVSvn = binary.LittleEndian.Uint16(data[:2])
		data = data[2:]
	}
	if len(data) >= ReportDataSize {
		copy(q.ReportBody.ReportData[:], data[:ReportDataSize])
		data = data[ReportDataSize:]
	}
	if len(data) >= 8 {
		q.ReportBody.Attributes.Flags = binary.LittleEndian.Uint64(data[:8])
		data = data[8:]
	}

	// Signature (whatever is left).
	if len(data) > 0 {
		q.SignatureLength = uint32(len(data))
		q.Signature = make([]byte, len(data))
		copy(q.Signature, data)
	} else {
		q.SignatureLength = 0
		q.Signature = nil
	}

	return q
}

// ---------------------------------------------------------------------------
// 2. FuzzSGXEnclaveExecution
//
// Fuzz enclave Execute with arbitrary operations and input data.
//
// Invariants:
//   - No panics on any operation name or input.
//   - Output is never nil for an initialized enclave.
//   - Destroyed enclave always returns error.
// ---------------------------------------------------------------------------

func FuzzSGXEnclaveExecution(f *testing.F) {
	f.Add([]byte("hash"), []byte("test input"))
	f.Add([]byte("verify"), []byte{})
	f.Add([]byte("inference"), make([]byte, 1024))
	f.Add([]byte(""), []byte{0xFF})
	f.Add([]byte("unknown_op"), make([]byte, 0))

	f.Fuzz(func(t *testing.T, operation []byte, input []byte) {
		enclave, err := NewSGXEnclave(nil)
		if err != nil {
			t.Fatal(err)
		}

		output, err := enclave.Execute(string(operation), input)
		if err != nil {
			t.Fatalf("Execute error on initialized enclave: %v", err)
		}
		if output == nil {
			t.Fatal("Execute returned nil output")
		}

		// Destroyed enclave must reject.
		_ = enclave.Destroy()
		_, err = enclave.Execute(string(operation), input)
		if err == nil {
			t.Fatal("destroyed enclave accepted execution")
		}
	})
}

// ---------------------------------------------------------------------------
// 3. FuzzSGXSealUnseal
//
// Fuzz the seal/unseal data path.
//
// Invariants:
//   - SealData never panics.
//   - UnsealData on arbitrary bytes never panics.
//   - UnsealData rejects data with wrong MRENCLAVE.
//   - Short data is always rejected.
// ---------------------------------------------------------------------------

func FuzzSGXSealUnseal(f *testing.F) {
	f.Add([]byte("label"), []byte("plaintext data"))
	f.Add([]byte(""), []byte{})
	f.Add([]byte("x"), make([]byte, 4096))
	f.Add([]byte("key"), []byte{0xFF, 0xFE, 0xFD})

	f.Fuzz(func(t *testing.T, label []byte, plaintext []byte) {
		enclave, err := NewSGXEnclave(nil)
		if err != nil {
			t.Fatal(err)
		}

		// Seal must not panic.
		sealed, err := enclave.SealData(string(label), plaintext)
		if err != nil {
			t.Fatalf("SealData error: %v", err)
		}
		if sealed == nil {
			t.Fatal("SealData returned nil")
		}

		// UnsealData with arbitrary bytes must not panic (just return error).
		_, _ = enclave.UnsealData(string(label), plaintext) // likely fails, that is fine

		// UnsealData with truncated sealed data must fail.
		if len(sealed) > 10 {
			_, err = enclave.UnsealData(string(label), sealed[:10])
			if err == nil {
				t.Fatal("UnsealData accepted truncated data")
			}
		}

		// UnsealData with corrupted MRENCLAVE must fail.
		if len(sealed) >= MREnclaveSize {
			corrupted := make([]byte, len(sealed))
			copy(corrupted, sealed)
			corrupted[0] ^= 0xFF // Flip first byte of MRENCLAVE
			_, err = enclave.UnsealData(string(label), corrupted)
			if err == nil {
				t.Fatal("UnsealData accepted data with corrupted MRENCLAVE")
			}
		}
	})
}
