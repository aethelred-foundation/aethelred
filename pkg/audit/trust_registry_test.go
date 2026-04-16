package audit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnterpriseControlLedgerTrustRegistry_ToSnapshotNormalizesEntries(t *testing.T) {
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signer key: %v", err)
	}

	registry := &EnterpriseControlLedgerTrustRegistry{
		Version:              "2026.04.14",
		Source:               "governance_registry",
		UpdatedAt:            "2026-04-14T10:15:00Z",
		RequiredAction:       defaultEnterpriseControlLedgerWriteAction,
		RequiredJurisdiction: "UAE",
		PolicySigners: []EnterprisePolicySignerTrustEntry{{
			DID:           "did:aethelred:policy-gateway-1",
			PublicKeyHex:  compressedP256PublicKeyHex(&signerKey.PublicKey),
			Actions:       []string{defaultEnterpriseControlLedgerWriteAction, defaultEnterpriseControlLedgerWriteAction, " "},
			Jurisdictions: []string{"UAE", "UAE", " "},
		}},
		AllowedSponsors: []EnterpriseSponsorTrustEntry{{
			DID:           "did:aethelred:sponsor-bank",
			Status:        TrustRegistryEntryStatusActive,
			Actions:       []string{defaultEnterpriseControlLedgerWriteAction, " "},
			Jurisdictions: []string{"UAE", "UAE"},
		}},
		Metadata: map[string]string{
			"channel": "finance",
		},
	}

	snapshot, err := registry.ToSnapshot()
	if err != nil {
		t.Fatalf("to snapshot: %v", err)
	}
	if snapshot.RequiredAction != defaultEnterpriseControlLedgerWriteAction {
		t.Fatalf("expected required action %q, got %q", defaultEnterpriseControlLedgerWriteAction, snapshot.RequiredAction)
	}
	if snapshot.Source != "governance_registry" {
		t.Fatalf("expected source governance_registry, got %q", snapshot.Source)
	}

	signerEntry := snapshot.PolicySigners["did:aethelred:policy-gateway-1"]
	if signerEntry.Status != TrustRegistryEntryStatusActive {
		t.Fatalf("expected active signer status, got %q", signerEntry.Status)
	}
	if len(signerEntry.Actions) != 1 || signerEntry.Actions[0] != defaultEnterpriseControlLedgerWriteAction {
		t.Fatalf("expected normalized signer actions, got %v", signerEntry.Actions)
	}
	if len(signerEntry.Jurisdictions) != 1 || signerEntry.Jurisdictions[0] != "UAE" {
		t.Fatalf("expected normalized signer jurisdictions, got %v", signerEntry.Jurisdictions)
	}

	sponsorEntry := snapshot.AllowedSponsors["did:aethelred:sponsor-bank"]
	if sponsorEntry.Status != TrustRegistryEntryStatusActive {
		t.Fatalf("expected active sponsor status, got %q", sponsorEntry.Status)
	}
	if len(sponsorEntry.Actions) != 1 || sponsorEntry.Actions[0] != defaultEnterpriseControlLedgerWriteAction {
		t.Fatalf("expected normalized sponsor actions, got %v", sponsorEntry.Actions)
	}
}

func TestFileEnterpriseControlLedgerTrustSource_ReloadsOnChange(t *testing.T) {
	registryPath := filepath.Join(t.TempDir(), "audit-enterprise-trust.json")
	writeRegistryFile := func(version string, jurisdiction string) {
		t.Helper()
		registry := newTrustRegistryForTest(t, version, jurisdiction)
		data, err := json.Marshal(registry)
		if err != nil {
			t.Fatalf("marshal registry: %v", err)
		}
		if err := os.WriteFile(registryPath, data, 0o600); err != nil {
			t.Fatalf("write registry file: %v", err)
		}
	}

	writeRegistryFile("v1", "UAE")
	firstModTime := time.Date(2026, 4, 14, 10, 0, 0, 0, time.UTC)
	if err := os.Chtimes(registryPath, firstModTime, firstModTime); err != nil {
		t.Fatalf("set initial registry modtime: %v", err)
	}

	source, err := NewFileEnterpriseControlLedgerTrustSource(registryPath)
	if err != nil {
		t.Fatalf("new file trust source: %v", err)
	}

	snapshotV1, err := source.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("load v1 snapshot: %v", err)
	}
	if snapshotV1.Version != "v1" || snapshotV1.RequiredJurisdiction != "UAE" {
		t.Fatalf("unexpected v1 snapshot: %+v", snapshotV1)
	}

	writeRegistryFile("v2", "UK")
	secondModTime := firstModTime.Add(2 * time.Second)
	if err := os.Chtimes(registryPath, secondModTime, secondModTime); err != nil {
		t.Fatalf("set updated registry modtime: %v", err)
	}

	snapshotV2, err := source.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("load v2 snapshot: %v", err)
	}
	if snapshotV2.Version != "v2" {
		t.Fatalf("expected reloaded version v2, got %q", snapshotV2.Version)
	}
	if snapshotV2.RequiredJurisdiction != "UK" {
		t.Fatalf("expected reloaded jurisdiction UK, got %q", snapshotV2.RequiredJurisdiction)
	}
}

func newTrustRegistryForTest(t *testing.T, version string, jurisdiction string) *EnterpriseControlLedgerTrustRegistry {
	t.Helper()

	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signer key: %v", err)
	}

	return &EnterpriseControlLedgerTrustRegistry{
		Version:              version,
		Source:               "test_registry_file",
		UpdatedAt:            "2026-04-14T10:00:00Z",
		RequiredAction:       defaultEnterpriseControlLedgerWriteAction,
		RequiredJurisdiction: jurisdiction,
		PolicySigners: []EnterprisePolicySignerTrustEntry{{
			DID:           "did:aethelred:policy-gateway-1",
			PublicKeyHex:  compressedP256PublicKeyHex(&signerKey.PublicKey),
			Status:        TrustRegistryEntryStatusActive,
			Actions:       []string{defaultEnterpriseControlLedgerWriteAction},
			Jurisdictions: []string{jurisdiction},
		}},
		AllowedSponsors: []EnterpriseSponsorTrustEntry{{
			DID:           "did:aethelred:sponsor-bank",
			Status:        TrustRegistryEntryStatusActive,
			Actions:       []string{defaultEnterpriseControlLedgerWriteAction},
			Jurisdictions: []string{jurisdiction},
		}},
	}
}

func compressedP256PublicKeyHex(pubKey *ecdsa.PublicKey) string {
	if pubKey == nil {
		return ""
	}
	return hex.EncodeToString(elliptic.MarshalCompressed(pubKey.Curve, pubKey.X, pubKey.Y))
}
