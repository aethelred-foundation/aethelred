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

// ---------------------------------------------------------------------------
// FuzzFrameworkValidation — fuzz framework validation with invariant checks.
//
// Invariants:
//   - Empty framework ID always causes Validate() to return error.
//   - Empty framework name always causes Validate() to return error.
//   - Empty framework version always causes Validate() to return error.
//   - Framework with no controls always causes Validate() to return error.
//   - Framework with valid ID + name + version + at least 1 valid control
//     must succeed validation.
//   - After successful validation, Controls count matches input.
//   - Coverage score must be in [0, 100] range.
// ---------------------------------------------------------------------------
func FuzzFrameworkValidation(f *testing.F) {
	f.Add("test-id", "Test Framework", "1.0", "CTRL-1", "Test Control", "A test control", "Test")
	f.Add("", "Test Framework", "1.0", "CTRL-1", "Test Control", "A test control", "Test")
	f.Add("test-id", "", "1.0", "CTRL-1", "Test Control", "A test control", "Test")
	f.Add("test-id", "Test Framework", "", "CTRL-1", "Test Control", "A test control", "Test")
	f.Add("nist-ai-rmf", "NIST AI RMF", "1.0", "GOV-1", "Governance", "AI governance control", "Govern")
	f.Add("a", "b", "c", "", "d", "e", "f")
	f.Add("a", "b", "c", "d", "", "e", "f")
	f.Add("a", "b", "c", "d", "e", "", "f")
	f.Add("a", "b", "c", "d", "e", "f", "")

	f.Fuzz(func(t *testing.T, id, name, version, ctrlID, ctrlName, ctrlDesc, ctrlCategory string) {
		// --- Test with one control ---
		fw := &compliance.Framework{
			ID:      id,
			Name:    name,
			Version: version,
			Controls: []compliance.Control{
				{
					ID:          ctrlID,
					Name:        ctrlName,
					Description: ctrlDesc,
					Category:    ctrlCategory,
				},
			},
		}

		err := fw.Validate()

		// Invariant: empty ID must fail
		if id == "" {
			if err == nil {
				t.Fatal("expected error for empty framework ID")
			}
			return // No further checks needed
		}

		// Invariant: empty name must fail
		if name == "" {
			if err == nil {
				t.Fatal("expected error for empty framework name")
			}
			return
		}

		// Invariant: empty version must fail
		if version == "" {
			if err == nil {
				t.Fatal("expected error for empty framework version")
			}
			return
		}

		// Invariant: control with empty ID must fail
		if ctrlID == "" {
			if err == nil {
				t.Fatal("expected error for empty control ID")
			}
			return
		}

		// Invariant: control with empty name must fail
		if ctrlName == "" {
			if err == nil {
				t.Fatal("expected error for empty control name")
			}
			return
		}

		// Invariant: control with empty description must fail
		if ctrlDesc == "" {
			if err == nil {
				t.Fatal("expected error for empty control description")
			}
			return
		}

		// Invariant: control with empty category must fail
		if ctrlCategory == "" {
			if err == nil {
				t.Fatal("expected error for empty control category")
			}
			return
		}

		// All fields are non-empty: validation must succeed
		if err != nil {
			t.Fatalf("expected validation success for valid framework, got: %v", err)
		}

		// Invariant: after successful validation, Controls count matches input
		if len(fw.Controls) != 1 {
			t.Fatalf("expected 1 control, got %d", len(fw.Controls))
		}

		// Invariant: coverage scores are in valid range [0, 100]
		levels := []compliance.CoverageLevel{
			compliance.CoverageFull,
			compliance.CoveragePartial,
			compliance.CoveragePlanned,
			compliance.CoverageNotApplicable,
			compliance.CoverageGap,
		}
		for _, level := range levels {
			score := level.Score()
			if score < 0 || score > 100 {
				t.Fatalf("CoverageLevel %v has score %d out of [0,100] range", level, score)
			}
		}

		// --- Test with zero controls: must fail ---
		fwNoControls := &compliance.Framework{
			ID:       id,
			Name:     name,
			Version:  version,
			Controls: []compliance.Control{},
		}
		if err := fwNoControls.Validate(); err == nil {
			t.Fatal("expected error for framework with no controls")
		}

		// --- Test with multiple controls including duplicates ---
		fwDuplicates := &compliance.Framework{
			ID:      id,
			Name:    name,
			Version: version,
			Controls: []compliance.Control{
				{ID: ctrlID, Name: ctrlName, Description: ctrlDesc, Category: ctrlCategory},
				{ID: ctrlID, Name: ctrlName, Description: ctrlDesc, Category: ctrlCategory},
			},
		}
		if err := fwDuplicates.Validate(); err == nil {
			t.Fatal("expected error for framework with duplicate control IDs")
		}
	})
}
