package keeper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnterprise_ActivateAndQueryEntry(t *testing.T) {
	reg := NewEnterpriseRegistry()

	hash := "abc123def456"
	sig := []byte("governance-signature-1")

	// Activate an entry.
	err := reg.ActivateEntry(hash, sig)
	require.NoError(t, err)

	// Query it back.
	require.True(t, reg.IsActive(hash))

	entry := reg.GetEntry(hash)
	require.NotNil(t, entry)
	require.Equal(t, hash, entry.Hash)
	require.Equal(t, RegistryStatusActive, entry.Status)
	require.Equal(t, sig, entry.Signature)
	require.False(t, entry.ActivatedAt.IsZero())
	require.True(t, entry.RevokedAt.IsZero())

	// Duplicate activation must fail.
	err = reg.ActivateEntry(hash, sig)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already active")

	// Unknown hash returns false / nil.
	require.False(t, reg.IsActive("unknown-hash"))
	require.Nil(t, reg.GetEntry("unknown-hash"))

	// Empty hash must fail.
	err = reg.ActivateEntry("", sig)
	require.Error(t, err)
	require.Contains(t, err.Error(), "hash cannot be empty")

	// Empty signature must fail.
	err = reg.ActivateEntry("new-hash", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "signature cannot be empty")
}

func TestEnterprise_RevokeEntry(t *testing.T) {
	reg := NewEnterpriseRegistry()

	hash := "measurement-hash-001"
	sig := []byte("gov-sig")

	// Activate first.
	require.NoError(t, reg.ActivateEntry(hash, sig))
	require.True(t, reg.IsActive(hash))

	// Revoke.
	err := reg.RevokeEntry(hash, "compromised firmware")
	require.NoError(t, err)

	// Entry should no longer be active.
	require.False(t, reg.IsActive(hash))

	// Entry should still exist with revoked status.
	entry := reg.GetEntry(hash)
	require.NotNil(t, entry)
	require.Equal(t, RegistryStatusRevoked, entry.Status)
	require.Equal(t, "compromised firmware", entry.RevokeReason)
	require.False(t, entry.RevokedAt.IsZero())

	// Double revocation must fail.
	err = reg.RevokeEntry(hash, "again")
	require.Error(t, err)
	require.Contains(t, err.Error(), "already revoked")

	// Revoking non-existent entry must fail.
	err = reg.RevokeEntry("nonexistent", "reason")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")

	// Empty hash must fail.
	err = reg.RevokeEntry("", "reason")
	require.Error(t, err)
	require.Contains(t, err.Error(), "hash cannot be empty")
}

func TestEnterprise_RevokedEntryRejectsVerification(t *testing.T) {
	reg := NewEnterpriseRegistry()

	hash := "circuit-hash-xyz"
	sig := []byte("authority-sig")

	// Activate, then revoke.
	require.NoError(t, reg.ActivateEntry(hash, sig))
	require.True(t, reg.IsActive(hash))

	require.NoError(t, reg.RevokeEntry(hash, "key rotation"))
	require.False(t, reg.IsActive(hash))

	// Re-activation of a revoked entry must be rejected.
	err := reg.ActivateEntry(hash, sig)
	require.Error(t, err)
	require.Contains(t, err.Error(), "revoked and cannot be re-activated")

	// A new, different hash can still be activated.
	newHash := "circuit-hash-xyz-v2"
	require.NoError(t, reg.ActivateEntry(newHash, sig))
	require.True(t, reg.IsActive(newHash))
	require.False(t, reg.IsActive(hash)) // original stays revoked
}

func TestEnterprise_RegistryVersionIncrements(t *testing.T) {
	reg := NewEnterpriseRegistry()

	// Initial version is 0.
	require.Equal(t, uint64(0), reg.GetRegistryVersion())

	// Activation increments version.
	require.NoError(t, reg.ActivateEntry("h1", []byte("sig")))
	require.Equal(t, uint64(1), reg.GetRegistryVersion())

	require.NoError(t, reg.ActivateEntry("h2", []byte("sig")))
	require.Equal(t, uint64(2), reg.GetRegistryVersion())

	// Revocation increments version.
	require.NoError(t, reg.RevokeEntry("h1", "rotated"))
	require.Equal(t, uint64(3), reg.GetRegistryVersion())

	// Failed operations do NOT increment version.
	_ = reg.ActivateEntry("h2", []byte("sig")) // already active
	require.Equal(t, uint64(3), reg.GetRegistryVersion())

	_ = reg.RevokeEntry("nonexistent", "reason") // not found
	require.Equal(t, uint64(3), reg.GetRegistryVersion())

	// Entry records the version at which it was activated.
	entry := reg.GetEntry("h2")
	require.NotNil(t, entry)
	require.Equal(t, uint64(2), entry.Version)
}

func TestEnterprise_JobRecordsRegistryVersions(t *testing.T) {
	reg := NewEnterpriseRegistry()

	// Set up some registry state.
	require.NoError(t, reg.ActivateEntry("m1", []byte("sig")))   // version 1
	require.NoError(t, reg.ActivateEntry("c1", []byte("sig")))   // version 2

	measurementVer := reg.GetRegistryVersion() // 2
	circuitVer := reg.GetRegistryVersion()     // 2

	// Record usage for a job.
	err := reg.RecordJobRegistryUsage("job-001", measurementVer, circuitVer)
	require.NoError(t, err)

	// Query usage.
	usage := reg.GetJobRegistryUsage("job-001")
	require.NotNil(t, usage)
	require.Equal(t, "job-001", usage.JobID)
	require.Equal(t, uint64(2), usage.MeasurementVersion)
	require.Equal(t, uint64(2), usage.CircuitVersion)
	require.False(t, usage.RecordedAt.IsZero())

	// Mutate registry (revoke + activate new entry).
	require.NoError(t, reg.RevokeEntry("m1", "upgrade"))         // version 3
	require.NoError(t, reg.ActivateEntry("m2", []byte("sig")))   // version 4

	// Record a second job with the new version.
	err = reg.RecordJobRegistryUsage("job-002", reg.GetRegistryVersion(), circuitVer)
	require.NoError(t, err)

	usage2 := reg.GetJobRegistryUsage("job-002")
	require.NotNil(t, usage2)
	require.Equal(t, uint64(4), usage2.MeasurementVersion)
	require.Equal(t, uint64(2), usage2.CircuitVersion)

	// Original job record is unchanged.
	usage1 := reg.GetJobRegistryUsage("job-001")
	require.Equal(t, uint64(2), usage1.MeasurementVersion)

	// Unknown job returns nil.
	require.Nil(t, reg.GetJobRegistryUsage("nonexistent-job"))

	// Empty jobID must fail.
	err = reg.RecordJobRegistryUsage("", 1, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "jobID cannot be empty")
}
