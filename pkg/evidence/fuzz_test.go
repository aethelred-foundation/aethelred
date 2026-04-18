package evidence

import (
	"encoding/json"
	"testing"
	"time"
)

func FuzzBundleSerialization(f *testing.F) {
	f.Add("SOC2", "audit", "action-test", "actor-1")
	f.Add("HIPAA", "computation", "deploy", "system")
	f.Add("", "", "", "")
	f.Add("NIST-800-53", "verification", "verify_seal", "did:aethelred:abc")

	f.Fuzz(func(t *testing.T, framework, recordType, action, actor string) {
		bundle := NewEvidenceBundle(framework)
		r := Record{
			ID:        "fuzz-record-001",
			Type:      recordType,
			Action:    action,
			Actor:     actor,
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Data:      map[string]string{"fuzz": "true"},
		}
		r.Hash = r.ComputeHash()
		bundle.AddRecord(r)

		// Finalize should not panic.
		err := bundle.Finalize("")
		if err != nil {
			return // Invalid bundles are expected in fuzzing.
		}

		// JSON round-trip should not panic.
		data, err := json.Marshal(bundle)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded EvidenceBundle
		err = json.Unmarshal(data, &decoded)
		if err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.ID != bundle.ID {
			t.Errorf("ID mismatch: %s vs %s", decoded.ID, bundle.ID)
		}
	})
}
