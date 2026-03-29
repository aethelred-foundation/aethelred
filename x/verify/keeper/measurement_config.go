package keeper

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// MeasurementConfigFile represents the shared TEE measurement configuration
// format consumed by both the Go and Rust layers for registry synchronization.
type MeasurementConfigFile struct {
	Version             int                                `json:"version"`
	Measurements        map[string]map[string][]string     `json:"measurements"`
	MinQuoteAgeSeconds  int64                              `json:"min_quote_age_seconds"`
	LastUpdated         time.Time                          `json:"last_updated"`
}

// LoadTrustedMeasurementsFromFile reads a shared TEE measurement config JSON file
// and returns a map of platform/field keys to decoded measurement byte slices.
//
// The returned map uses keys of the form "platform:field" (e.g. "aws-nitro:pcr0",
// "intel-sgx:mrenclave") mapped to slices of hex-decoded measurement values.
func LoadTrustedMeasurementsFromFile(path string) (map[string][]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading measurement config: %w", err)
	}
	return ParseTrustedMeasurementsJSON(data)
}

// ParseTrustedMeasurementsJSON parses the shared measurement config JSON and
// returns a flat map of "platform:field" -> []hex_measurement_strings.
// Each hex string is validated to ensure it decodes to valid bytes.
func ParseTrustedMeasurementsJSON(data []byte) (map[string][]string, error) {
	var config MeasurementConfigFile
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing measurement config JSON: %w", err)
	}

	if config.Version != 1 {
		return nil, fmt.Errorf("unsupported measurement config version: %d", config.Version)
	}

	if len(config.Measurements) == 0 {
		return nil, fmt.Errorf("measurement config contains no platforms")
	}

	result := make(map[string][]string)
	for platform, fields := range config.Measurements {
		platform = strings.TrimSpace(platform)
		if platform == "" {
			continue
		}
		for field, measurements := range fields {
			field = strings.TrimSpace(field)
			if field == "" {
				continue
			}
			key := platform + ":" + field
			for _, hexStr := range measurements {
				hexStr = strings.TrimSpace(hexStr)
				if hexStr == "" {
					continue
				}
				// Validate hex encoding
				if _, err := hex.DecodeString(hexStr); err != nil {
					return nil, fmt.Errorf("invalid hex measurement %q for %s: %w", hexStr, key, err)
				}
				result[key] = append(result[key], hexStr)
			}
		}
	}

	return result, nil
}

// DecodeMeasurements takes the flat map from ParseTrustedMeasurementsJSON and
// decodes all hex strings into byte slices for a given key.
func DecodeMeasurements(measurements map[string][]string, key string) ([][]byte, error) {
	hexStrings, ok := measurements[key]
	if !ok {
		return nil, nil
	}
	result := make([][]byte, 0, len(hexStrings))
	for _, h := range hexStrings {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("decoding measurement %q: %w", h, err)
		}
		result = append(result, b)
	}
	return result, nil
}
