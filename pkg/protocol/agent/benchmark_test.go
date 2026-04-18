package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

func BenchmarkCreateIdentity(b *testing.B) {
	caps := []Capability{
		{Name: "compute.execute", Version: "1.0"},
		{Name: "model.deploy", Version: "1.0"},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = NewAgentIdentity(caps)
	}
}

func BenchmarkIssueCredential(b *testing.B) {
	issuerID, issuerKey, err := NewAgentIdentity(nil)
	if err != nil {
		b.Fatalf("setup: NewAgentIdentity failed: %v", err)
	}
	subjectID, _, err := NewAgentIdentity(nil)
	if err != nil {
		b.Fatalf("setup: NewAgentIdentity (subject) failed: %v", err)
	}
	ctx := context.Background()
	claims := []Claim{{Name: "compute.execute", Value: "true", Verified: true}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = IssueCredential(ctx, issuerKey, issuerID.DID.String(), subjectID.DID.String(), CapabilityCredential, claims, 24*time.Hour)
	}
}

func BenchmarkVerifyCredential(b *testing.B) {
	issuerID, issuerKey, _ := NewAgentIdentity(nil)
	subjectID, _, _ := NewAgentIdentity(nil)
	ctx := context.Background()
	claims := []Claim{{Name: "compute.execute", Value: "true", Verified: true}}
	cred, err := IssueCredential(ctx, issuerKey, issuerID.DID.String(), subjectID.DID.String(), CapabilityCredential, claims, 24*time.Hour)
	if err != nil {
		b.Fatalf("setup: IssueCredential failed: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VerifyCredential(cred, issuerID.PublicKey)
	}
}

func BenchmarkDelegation(b *testing.B) {
	dm := NewDelegationManager()
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parent, _ := dm.Delegate(ctx, "did:aethelred:root", "did:aethelred:child1", &DelegationScope{
			Actions:  []string{"compute.execute"},
			MaxDepth: 3,
		}, nil)
		if parent != nil {
			child, _ := dm.SubDelegate(ctx, parent.ID, "did:aethelred:child2", &DelegationScope{
				Actions:  []string{"compute.execute"},
				MaxDepth: 2,
			}, nil)
			if child != nil {
				_, _ = dm.SubDelegate(ctx, child.ID, "did:aethelred:child3", &DelegationScope{
					Actions:  []string{"compute.execute"},
					MaxDepth: 1,
				}, nil)
			}
		}
	}
}

func BenchmarkVerifyDelegation(b *testing.B) {
	dm := NewDelegationManager()
	ctx := context.Background()
	del, _ := dm.Delegate(ctx, "did:aethelred:root", "did:aethelred:child", &DelegationScope{
		Actions:  []string{"compute.execute"},
		MaxDepth: 1,
	}, nil)
	if del == nil {
		b.Fatal("setup: Delegate returned nil")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = dm.VerifyDelegation(ctx, del.ID, "compute.execute")
	}
}

func BenchmarkCreateReceipt(b *testing.B) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("setup: key generation failed: %v", err)
	}
	ctx := context.Background()
	evidence := map[string]string{"model_hash": "abc123", "output_hash": "def456"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CreateReceipt(ctx, key, "did:aethelred:agent1", "compute.execute", "model-123", "success", "", evidence)
	}
}
