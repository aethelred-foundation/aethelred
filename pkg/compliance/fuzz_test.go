package compliance_test

import (
	"testing"

	"github.com/aethelred/aethelred/pkg/compliance"
)

func FuzzParseCoverageLevel(f *testing.F) {
	f.Add("full")
	f.Add("Full")
	f.Add("partial")
	f.Add("planned")
	f.Add("not applicable")
	f.Add("not_applicable")
	f.Add("n/a")
	f.Add("gap")
	f.Add("")
	f.Add("invalid")
	f.Add("FULL")
	f.Add("  full  ")

	f.Fuzz(func(t *testing.T, input string) {
		level, err := compliance.ParseCoverageLevel(input)
		if err == nil {
			// If parsing succeeds, the level should have a valid string representation.
			s := level.String()
			if s == "" {
				t.Errorf("parsed %q but String() returned empty", input)
			}
			// Score should be in [0, 100].
			score := level.Score()
			if score < 0 || score > 100 {
				t.Errorf("parsed %q: score %d out of range [0,100]", input, score)
			}
		}
	})
}

func FuzzFrameworkValidation(f *testing.F) {
	f.Add("test-id", "Test Framework", "1.0")
	f.Add("", "Test Framework", "1.0")
	f.Add("test-id", "", "1.0")
	f.Add("test-id", "Test Framework", "")
	f.Add("nist-ai-rmf", "NIST AI RMF", "1.0")
	f.Add("a", "b", "c")

	f.Fuzz(func(t *testing.T, id, name, version string) {
		fw := &compliance.Framework{
			ID:      id,
			Name:    name,
			Version: version,
			Controls: []compliance.Control{
				{
					ID:          "CTRL-1",
					Name:        "Test Control",
					Description: "A test control",
					Category:    "Test",
				},
			},
		}
		// Validate should not panic regardless of input.
		_ = fw.Validate()
	})
}
