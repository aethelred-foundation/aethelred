package keeper_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

func TestKeeper_EnterpriseAuditTrustRegistryRoundTrip(t *testing.T) {
	k, ctx := newTestKeeper(t)

	registry := newEnterpriseAuditTrustRegistry(t)
	require.NoError(t, k.SetEnterpriseAuditTrustRegistry(ctx, registry))

	stored, err := k.GetEnterpriseAuditTrustRegistry(ctx)
	require.NoError(t, err)
	require.Equal(t, "2026.04.14", stored.Version)
	require.Equal(t, "audit.control_ledger.write", stored.RequiredAction)
	require.Len(t, stored.PolicySigners, 1)
	require.Len(t, stored.AllowedSponsors, 1)

	status, err := k.GetEnterpriseAuditTrustRegistryStatus(ctx)
	require.NoError(t, err)
	require.True(t, status.Configured)
	require.Equal(t, 1, status.PolicySignerCount)
	require.Equal(t, 1, status.ActivePolicySignerCount)
	require.Equal(t, 1, status.AllowedSponsorCount)
	require.Equal(t, 1, status.ActiveSponsorCount)
}

func TestKeeper_EnterpriseAuditTrustRegistryRejectsInvalidSignerKey(t *testing.T) {
	k, ctx := newTestKeeper(t)

	registry := newEnterpriseAuditTrustRegistry(t)
	registry.PolicySigners[0].PublicKeyHex = "bad-key"

	err := k.SetEnterpriseAuditTrustRegistry(ctx, registry)
	require.Error(t, err)
	require.Contains(t, err.Error(), "public key")
}

func TestKeeper_EnterpriseAuditTrustRegistryClear(t *testing.T) {
	k, ctx := newTestKeeper(t)

	require.NoError(t, k.SetEnterpriseAuditTrustRegistry(ctx, newEnterpriseAuditTrustRegistry(t)))
	require.NoError(t, k.ClearEnterpriseAuditTrustRegistry(ctx))

	_, err := k.GetEnterpriseAuditTrustRegistry(ctx)
	require.ErrorIs(t, err, keeper.ErrEnterpriseAuditTrustRegistryNotConfigured)
}

func newEnterpriseAuditTrustRegistry(t *testing.T) *keeper.EnterpriseAuditTrustRegistry {
	t.Helper()

	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return &keeper.EnterpriseAuditTrustRegistry{
		Version:              "2026.04.14",
		Source:               "keeper_test",
		RequiredAction:       "audit.control_ledger.write",
		RequiredJurisdiction: "UAE",
		PolicySigners: []keeper.EnterpriseAuditPolicySignerTrustEntry{{
			DID:           "did:aethelred:policy-gateway-1",
			PublicKeyHex:  hex.EncodeToString(elliptic.MarshalCompressed(signerKey.PublicKey.Curve, signerKey.PublicKey.X, signerKey.PublicKey.Y)),
			Status:        keeper.EnterpriseAuditTrustEntryStatusActive,
			Actions:       []string{"audit.control_ledger.write"},
			Jurisdictions: []string{"UAE"},
		}},
		AllowedSponsors: []keeper.EnterpriseAuditSponsorTrustEntry{{
			DID:           "did:aethelred:sponsor-bank",
			Status:        keeper.EnterpriseAuditTrustEntryStatusActive,
			Actions:       []string{"audit.control_ledger.write"},
			Jurisdictions: []string{"UAE"},
		}},
		Metadata: map[string]string{
			"channel": "finance",
		},
	}
}
