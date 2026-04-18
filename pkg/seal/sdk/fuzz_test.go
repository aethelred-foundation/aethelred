package sdk

import (
	"testing"

	"github.com/aethelred/aethelred/x/seal/types"
)

func FuzzSealExportImportJSON(f *testing.F) {
	f.Add([]byte("model-hash-data-for-seal-test1"), []byte("input-hash-data-for-seal-test1"), []byte("output-data-for-seal-test1"))
	f.Add([]byte("short"), []byte("another-short"), []byte("out"))
	f.Add([]byte{}, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, modelData, inputData, outputData []byte) {
		modelHash := ComputeHash(modelData)
		inputHash := ComputeHash(inputData)
		outputHash := ComputeHash(outputData)

		seal := types.NewDigitalSeal(modelHash, inputHash, outputHash, 1, "aethelred1fuzz", "fuzz-test")

		exported, err := ExportJSON(seal)
		if err != nil {
			// Export should work for any valid seal.
			t.Fatalf("ExportJSON failed: %v", err)
		}

		imported, err := ImportJSON(exported)
		if err != nil {
			t.Fatalf("ImportJSON failed on exported data: %v", err)
		}

		// Round-trip: re-export should produce identical output.
		reexported, err := ExportJSON(imported)
		if err != nil {
			t.Fatalf("re-export failed: %v", err)
		}

		if string(exported) != string(reexported) {
			t.Errorf("round-trip mismatch: lengths %d vs %d", len(exported), len(reexported))
		}
	})
}

func FuzzComputeHash(f *testing.F) {
	f.Add([]byte("hello world"))
	f.Add([]byte(""))
	f.Add([]byte{0x00, 0xFF, 0xAB})
	f.Add(make([]byte, 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		h := ComputeHash(data)
		if len(h) != 32 {
			t.Errorf("expected 32-byte hash, got %d bytes", len(h))
		}

		// Deterministic: same input gives same output.
		h2 := ComputeHash(data)
		for j := range h {
			if h[j] != h2[j] {
				t.Fatal("ComputeHash is not deterministic")
			}
		}
	})
}
