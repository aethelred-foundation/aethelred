//go:build !production

package app

// allow_simulated_dev.go — development/test build defaults.
//
// This file is included in all non-production builds (default).
// It provides the same symbols as allow_simulated_prod.go but
// with development-mode defaults.

// productionMode is false in dev/test builds.
var productionMode bool

// IsProductionBuild returns false in dev/test builds.
func IsProductionBuild() bool {
	return false
}
