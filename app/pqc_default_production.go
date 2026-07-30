//go:build production

package app

// Production binaries select the fail-closed CIRCL-backed mode unless an
// operator explicitly configures another supported policy.
const defaultPQCMode = "production"

const (
	defaultPQCEnabled        = true
	requirePQCInitialization = true
)
