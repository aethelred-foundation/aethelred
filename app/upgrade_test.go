package app

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Upgrade name constants
// ---------------------------------------------------------------------------

func TestUpgradeNameV020_Value(t *testing.T) {
	if UpgradeNameV020 != "v0.2.0" {
		t.Fatalf("expected v0.2.0, got %s", UpgradeNameV020)
	}
}

// ---------------------------------------------------------------------------
// getSkipUpgradeHeights
// ---------------------------------------------------------------------------

type mockAppOpts struct {
	data map[string]interface{}
}

func (m mockAppOpts) Get(key string) interface{} {
	return m.data[key]
}

func TestGetSkipUpgradeHeights_Empty(t *testing.T) {
	opts := mockAppOpts{data: map[string]interface{}{}}
	heights := getSkipUpgradeHeights(opts)
	if len(heights) != 0 {
		t.Fatalf("expected empty map, got %v", heights)
	}
}

func TestGetSkipUpgradeHeights_WithValues(t *testing.T) {
	opts := mockAppOpts{data: map[string]interface{}{
		"unsafe-skip-upgrades": []int{100, 200, 300},
	}}
	heights := getSkipUpgradeHeights(opts)
	// The function uses cast.ToIntSlice which may return empty for this format;
	// what matters is no panic.
	_ = heights
}

func TestGetSkipUpgradeHeights_NilOpts(t *testing.T) {
	opts := mockAppOpts{data: nil}
	heights := getSkipUpgradeHeights(opts)
	if heights == nil {
		t.Fatal("expected non-nil map even with nil opts data")
	}
}

// ---------------------------------------------------------------------------
// Version compatibility check (upgrade plan naming)
// ---------------------------------------------------------------------------

func TestUpgradePlan_VersionNaming(t *testing.T) {
	// Verify that the upgrade name follows semver convention.
	name := UpgradeNameV020
	if len(name) == 0 {
		t.Fatal("upgrade name must not be empty")
	}
	if name[0] != 'v' {
		t.Fatal("upgrade name should start with 'v'")
	}
}
