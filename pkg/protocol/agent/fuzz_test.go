package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func FuzzParseDID(f *testing.F) {
	f.Add("did:aethelred:abc123")
	f.Add("did:aethelred:abc123#key-1")
	f.Add("")
	f.Add("invalid")
	f.Add("did:wrong:method")
	f.Add("did:aethelred:")
	f.Add("did:aethelred:id#")
	f.Add("did:aethelred:id#frag.with.dots")
	f.Add("did:aethelred:id#frag-with-hyphens_and_underscores")
	f.Add("did:aethelred:id#bad!char")

	f.Fuzz(func(t *testing.T, input string) {
		did, err := ParseDID(input)
		if err == nil {
			// If parsing succeeded, formatting should round-trip.
			identity := &AgentIdentity{DID: did}
			formatted := FormatDID(identity)
			if formatted == "" {
				t.Errorf("FormatDID returned empty for parsed DID %q", input)
			}
			// Re-parse should succeed.
			_, err2 := ParseDID(formatted)
			if err2 != nil {
				t.Errorf("round-trip failed: parsed %q, formatted to %q, but re-parse failed: %v", input, formatted, err2)
			}
		}
		// No panic is the primary check.
	})
}

func FuzzCredentialSerialization(f *testing.F) {
	f.Add("did:aethelred:issuer1", "did:aethelred:subject1", "capability", "claim-name", "claim-value")
	f.Add("", "", "", "", "")
	f.Add("did:aethelred:a", "did:aethelred:b", "authorization", "execute", "true")

	f.Fuzz(func(t *testing.T, issuerDID, subjectDID, credTypeStr, claimName, claimValue string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return // Key gen failure is not a test concern.
		}

		ctx := context.Background()
		claims := []Claim{{Name: claimName, Value: claimValue, Verified: true}}

		cred, err := IssueCredential(ctx, key, issuerDID, subjectDID, CapabilityCredential, claims, 24*time.Hour)
		if err != nil {
			return // Invalid input is expected.
		}

		// Serialize to JSON.
		data, err := json.Marshal(cred)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		// Deserialize from JSON.
		var decoded AgentCredential
		err = json.Unmarshal(data, &decoded)
		if err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		// Basic round-trip checks.
		if decoded.ID != cred.ID {
			t.Errorf("ID mismatch: %s vs %s", decoded.ID, cred.ID)
		}
		if decoded.Issuer != cred.Issuer {
			t.Errorf("Issuer mismatch: %s vs %s", decoded.Issuer, cred.Issuer)
		}
	})
}
