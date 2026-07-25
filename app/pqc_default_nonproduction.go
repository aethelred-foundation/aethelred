//go:build !production

package app

// Non-production binaries remain safe for local development and tests without
// requiring the optional CIRCL backend.
const defaultPQCMode = "simulated"

const (
	defaultPQCEnabled        = false
	requirePQCInitialization = false
)
