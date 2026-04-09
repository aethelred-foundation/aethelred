package sovereign

import (
	"context"
	"testing"
)

// ---------------------------------------------------------------------------
// FuzzRegionRouting
// ---------------------------------------------------------------------------

// FuzzRegionRouting fuzzes region IDs and residency policies to verify
// that the region controller correctly routes computations and enforces
// data residency constraints.
//
// Invariants:
//   - Blocked regions are always rejected by IsRegionAllowed.
//   - Allowed regions (when specified) restrict to the allow list.
//   - Empty region IDs produce errors from RouteComputation.
//   - No panics regardless of input.
func FuzzRegionRouting(f *testing.F) {
	// Seed: real region IDs
	f.Add("eu-west-1", "us-east-1", true, true)
	f.Add("us-east-1", "eu-west-1", false, false)
	f.Add("uae-dubai-1", "au-east-1", true, false)
	f.Add("", "", false, false)
	f.Add("nonexistent-region", "also-nonexistent", true, true)
	f.Add("sg-central-1", "jp-east-1", false, true)
	f.Add("\x00\xff", "\t\n", false, false)

	f.Fuzz(func(t *testing.T, regionID, blockedRegion string, requireEncryption, useAllowedList bool) {
		policy := &DataResidencyPolicy{
			RequireEncryptionInTransit: requireEncryption,
		}
		if blockedRegion != "" {
			policy.BlockedRegions = []string{blockedRegion}
		}
		if useAllowedList && regionID != "" {
			policy.AllowedRegions = []string{regionID}
		}

		// Invariant 1: blocked region is always rejected
		if blockedRegion != "" {
			if policy.IsRegionAllowed(blockedRegion) {
				t.Errorf("blocked region %q should not be allowed", blockedRegion)
			}
		}

		// Invariant 2: allowed region (when in list) is permitted
		if useAllowedList && regionID != "" && regionID != blockedRegion {
			if !policy.IsRegionAllowed(regionID) {
				t.Errorf("region %q in allowed list should be permitted", regionID)
			}
		}

		// Invariant 3: region not in allowed list is rejected (when list specified)
		if useAllowedList && regionID != "" {
			otherRegion := regionID + "-other"
			if otherRegion != blockedRegion && policy.IsRegionAllowed(otherRegion) {
				t.Errorf("region %q not in allowed list should be rejected", otherRegion)
			}
		}

		// Test routing through the controller
		rc := NewRegionController()

		job := ComputationJob{
			ID:         "fuzz-job",
			DataRegion: regionID,
		}

		_, err := rc.RouteComputation(context.Background(), job, policy)

		// Invariant 4: empty region ID produces error
		if regionID == "" && err == nil {
			t.Error("empty data region should produce routing error")
		}

		// Invariant 5: unknown region produces error
		if regionID != "" {
			known := false
			for _, r := range AllRegions() {
				if r.ID == regionID {
					known = true
					break
				}
			}
			if !known && err == nil {
				t.Errorf("unknown region %q should produce routing error", regionID)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// FuzzDeploymentSpecValidation
// ---------------------------------------------------------------------------

// FuzzDeploymentSpecValidation fuzzes deployment specification fields to
// verify that validation catches missing required fields.
//
// Invariants:
//   - Empty name always fails validation.
//   - Empty region always fails validation.
//   - Invalid TLS versions fail validation.
//   - Valid specs pass validation.
//   - No panics regardless of input.
func FuzzDeploymentSpecValidation(f *testing.F) {
	f.Add("my-deployment", "eu-west-1", "1.3", true)
	f.Add("", "", "", false)
	f.Add("deploy-us", "us-east-1", "1.2", true)
	f.Add("test", "region", "1.0", false)
	f.Add("d", "r", "99.99", true)
	f.Add("\x00\xff", "\t\n", "abc", false)
	f.Add("name", "region", "", true)

	f.Fuzz(func(t *testing.T, name, region, tlsVersion string, teeRequired bool) {
		spec := &DeploymentSpec{
			Name:   name,
			Region: region,
			Network: NetworkConfig{
				TLSMinVersion: tlsVersion,
			},
			Compute: ComputeConfig{
				TEERequired: teeRequired,
			},
		}

		err := spec.Validate()

		// Invariant 1: empty name fails
		if name == "" && err == nil {
			t.Error("spec with empty name must fail validation")
		}

		// Invariant 2: empty region fails
		if region == "" && err == nil {
			t.Error("spec with empty region must fail validation")
		}

		// Invariant 3: invalid TLS version fails
		if tlsVersion != "" && tlsVersion != "1.2" && tlsVersion != "1.3" {
			if err == nil {
				t.Errorf("spec with TLS version %q should fail validation", tlsVersion)
			}
		}

		// Invariant 4: valid spec passes
		if name != "" && region != "" && (tlsVersion == "" || tlsVersion == "1.2" || tlsVersion == "1.3") {
			if err != nil {
				t.Errorf("valid spec should pass validation: %v", err)
			}
		}

		// Also test TLS version validation directly
		tlsErr := ValidateTLSVersion(tlsVersion)
		if tlsVersion == "" {
			if tlsErr != nil {
				t.Errorf("empty TLS version should be valid (optional): %v", tlsErr)
			}
		} else if tlsVersion == "1.2" || tlsVersion == "1.3" {
			if tlsErr != nil {
				t.Errorf("TLS %q should be valid: %v", tlsVersion, tlsErr)
			}
		} else {
			if tlsErr == nil {
				t.Errorf("TLS %q should be invalid", tlsVersion)
			}
		}
	})
}
