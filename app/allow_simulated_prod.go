//go:build production

package app

// allow_simulated_prod.go - compile-time assertion for production builds.
//
// This file is only included when building with -tags production.
// It provides a runtime init() check to ensure AllowSimulated is never
// inadvertently hardcoded to true in production genesis or params.
//
// Usage: go build -tags production ./...
//
// If AllowSimulated is set to true in production genesis, the node will
// refuse to start with a clear error message.

func init() {
	// Register a production-mode assertion that will be checked
	// during app construction. The actual enforcement happens in
	// readiness.go where params.AllowSimulated is checked.
	// This init() serves as documentation + a hook for future
	// compile-time constraints.
	productionMode = true
}

// productionMode is set to true only in production builds.
// readiness.go and verification_pipeline.go check this flag.
var productionMode bool

// IsProductionBuild returns true when compiled with -tags production.
func IsProductionBuild() bool {
	return productionMode
}
