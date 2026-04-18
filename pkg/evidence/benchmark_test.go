package evidence

import (
	"fmt"
	"testing"
	"time"
)

func benchMakeBundle(n int) *EvidenceBundle {
	bundle := NewEvidenceBundle("SOC2")
	for i := 0; i < n; i++ {
		r := Record{
			ID:        fmt.Sprintf("rec-%d", i),
			Type:      "audit",
			Action:    fmt.Sprintf("action_%d", i),
			Actor:     fmt.Sprintf("actor_%d", i%5),
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Data:      map[string]string{"key": fmt.Sprintf("value_%d", i)},
		}
		r.Hash = r.ComputeHash()
		bundle.AddRecord(r)
	}
	bundle.AddSeal(Seal{
		SealID:         "seal-bench-001",
		JobID:          "job-bench-001",
		OutputHash:     "abc123",
		ValidatorCount: 3,
		BlockHeight:    1000,
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
	})
	bundle.AddAttestation(Attestation{
		ID:        "att-bench-001",
		Type:      "tee",
		Platform:  "aws-nitro",
		EnclaveID: "enclave-001",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	})
	return bundle
}

func BenchmarkBundleFinalize(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bundle := benchMakeBundle(100)
		_ = bundle.Finalize("")
	}
}

func BenchmarkBundleVerify(b *testing.B) {
	bundle := benchMakeBundle(100)
	_ = bundle.Finalize("")
	verifier := NewStandaloneVerifier([]string{"aws-nitro", "intel-sgx"}, false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = verifier.VerifyBundle(bundle)
	}
}

func BenchmarkCustodyTransfer(b *testing.B) {
	chain, _ := RecordCreation("initial-custodian")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		from := fmt.Sprintf("custodian-%d", i%10)
		to := fmt.Sprintf("custodian-%d", (i+1)%10)
		if from == to {
			to = fmt.Sprintf("custodian-%d", (i+2)%10)
		}
		var err error
		chain, err = RecordTransfer(chain, from, to)
		if err != nil {
			b.Fatalf("RecordTransfer failed: %v", err)
		}
	}
}
