package keeper

import (
	"os"
	"path/filepath"
	"testing"
)

// Shared config JSON used by both Go and Rust tests to validate cross-layer
// measurement config synchronization.
const testMeasurementConfigJSON = `{
  "version": 1,
  "measurements": {
    "aws-nitro": {
      "pcr0": [
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
      ],
      "pcr1": [
        "1111111111111111111111111111111111111111111111111111111111111111"
      ]
    },
    "intel-sgx": {
      "mrenclave": [
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      ],
      "mrsigner": [
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
      ]
    },
    "amd-sev": {
      "measurement": [
        "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
      ]
    }
  },
  "min_quote_age_seconds": 300,
  "last_updated": "2026-03-27T00:00:00Z"
}`

func TestMeasurementConfig_ParseJSON(t *testing.T) {
	result, err := ParseTrustedMeasurementsJSON([]byte(testMeasurementConfigJSON))
	if err != nil {
		t.Fatalf("ParseTrustedMeasurementsJSON failed: %v", err)
	}

	// Verify all expected keys exist
	expectedKeys := []string{
		"aws-nitro:pcr0",
		"aws-nitro:pcr1",
		"intel-sgx:mrenclave",
		"intel-sgx:mrsigner",
		"amd-sev:measurement",
	}
	for _, key := range expectedKeys {
		if _, ok := result[key]; !ok {
			t.Errorf("expected key %q not found in result", key)
		}
	}

	// Verify counts
	if len(result["aws-nitro:pcr0"]) != 2 {
		t.Errorf("expected 2 pcr0 measurements, got %d", len(result["aws-nitro:pcr0"]))
	}
	if len(result["intel-sgx:mrenclave"]) != 2 {
		t.Errorf("expected 2 mrenclave measurements, got %d", len(result["intel-sgx:mrenclave"]))
	}
	if len(result["intel-sgx:mrsigner"]) != 1 {
		t.Errorf("expected 1 mrsigner measurement, got %d", len(result["intel-sgx:mrsigner"]))
	}
	if len(result["amd-sev:measurement"]) != 1 {
		t.Errorf("expected 1 sev measurement, got %d", len(result["amd-sev:measurement"]))
	}

	// Verify specific values
	if result["aws-nitro:pcr0"][0] != "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2" {
		t.Errorf("unexpected pcr0 value: %s", result["aws-nitro:pcr0"][0])
	}
}

func TestMeasurementConfig_DecodeMeasurements(t *testing.T) {
	result, err := ParseTrustedMeasurementsJSON([]byte(testMeasurementConfigJSON))
	if err != nil {
		t.Fatalf("ParseTrustedMeasurementsJSON failed: %v", err)
	}

	// Decode SGX mrenclave measurements
	decoded, err := DecodeMeasurements(result, "intel-sgx:mrenclave")
	if err != nil {
		t.Fatalf("DecodeMeasurements failed: %v", err)
	}
	if len(decoded) != 2 {
		t.Fatalf("expected 2 decoded mrenclave measurements, got %d", len(decoded))
	}
	if len(decoded[0]) != 32 {
		t.Errorf("expected 32-byte measurement, got %d bytes", len(decoded[0]))
	}

	// Decode non-existent key returns nil
	missing, err := DecodeMeasurements(result, "nonexistent:key")
	if err != nil {
		t.Fatalf("DecodeMeasurements for missing key failed: %v", err)
	}
	if missing != nil {
		t.Errorf("expected nil for missing key, got %v", missing)
	}
}

func TestMeasurementConfig_LoadFromFile(t *testing.T) {
	// Write temp file
	dir := t.TempDir()
	path := filepath.Join(dir, "tee-measurements.json")
	if err := os.WriteFile(path, []byte(testMeasurementConfigJSON), 0644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	result, err := LoadTrustedMeasurementsFromFile(path)
	if err != nil {
		t.Fatalf("LoadTrustedMeasurementsFromFile failed: %v", err)
	}

	if len(result) != 5 {
		t.Errorf("expected 5 keys, got %d", len(result))
	}
}

func TestMeasurementConfig_InvalidVersion(t *testing.T) {
	invalidJSON := `{"version": 99, "measurements": {}}`
	_, err := ParseTrustedMeasurementsJSON([]byte(invalidJSON))
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestMeasurementConfig_InvalidHex(t *testing.T) {
	badHex := `{
		"version": 1,
		"measurements": {
			"aws-nitro": {
				"pcr0": ["not-valid-hex!"]
			}
		},
		"min_quote_age_seconds": 300,
		"last_updated": "2026-03-27T00:00:00Z"
	}`
	_, err := ParseTrustedMeasurementsJSON([]byte(badHex))
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestMeasurementConfig_EmptyMeasurements(t *testing.T) {
	emptyJSON := `{"version": 1, "measurements": {}, "min_quote_age_seconds": 300, "last_updated": "2026-03-27T00:00:00Z"}`
	_, err := ParseTrustedMeasurementsJSON([]byte(emptyJSON))
	if err == nil {
		t.Fatal("expected error for empty measurements")
	}
}

func TestMeasurementConfig_SharedFormatParity(t *testing.T) {
	// This test validates that the Go parser produces the same structure
	// as expected by the Rust from_config_json parser, ensuring cross-layer
	// measurement synchronization.
	result, err := ParseTrustedMeasurementsJSON([]byte(testMeasurementConfigJSON))
	if err != nil {
		t.Fatalf("ParseTrustedMeasurementsJSON failed: %v", err)
	}

	// Validate all platform types are present
	platforms := map[string]bool{
		"aws-nitro":  false,
		"intel-sgx":  false,
		"amd-sev":    false,
	}
	for key := range result {
		for p := range platforms {
			if len(key) > len(p) && key[:len(p)] == p {
				platforms[p] = true
			}
		}
	}
	for p, found := range platforms {
		if !found {
			t.Errorf("platform %q not found in parsed config", p)
		}
	}

	// Validate that all measurements are 32 bytes when decoded (64 hex chars)
	for key, hexStrs := range result {
		for _, h := range hexStrs {
			if len(h) != 64 {
				t.Errorf("key %s: expected 64 hex chars (32 bytes), got %d chars", key, len(h))
			}
		}
	}
}
