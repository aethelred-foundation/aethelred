package confidential

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"testing"
)

func mpcTestCluster(t *testing.T, n int, colocated bool) *MPCCluster {
	t.Helper()
	parties := make([]MPCParty, n)
	for i := range parties {
		parties[i] = LocalParty{Name: fmt.Sprintf("party-%d", i)}
	}
	c, err := NewMPCCluster(parties, colocated, "EU", "mpc-coordinator")
	if err != nil {
		t.Fatalf("cluster: %v", err)
	}
	return c
}

// TestMPC_RoundTrip proves the protocol is real: the input is additively
// shared, each party computes only on its share, and the reconstructed result
// matches the plaintext model within fixed-point precision.
func TestMPC_RoundTrip(t *testing.T) {
	for _, n := range []int{2, 3, 5} {
		cluster := mpcTestCluster(t, n, false)
		model := fheTestModel()
		if err := cluster.RegisterModel(model); err != nil {
			t.Fatalf("register: %v", err)
		}

		x := []float64{1.5, -2.0, 0.75}
		want, err := model.Apply(x)
		if err != nil {
			t.Fatalf("plaintext apply: %v", err)
		}

		in, err := cluster.EncryptInput(x)
		if err != nil {
			t.Fatalf("share: %v", err)
		}
		got, err := cluster.Evaluate(context.Background(), in, ModelRef{ModelID: model.ID, ModelHash: model.Hash()})
		if err != nil {
			t.Fatalf("evaluate (n=%d): %v", n, err)
		}
		for i := range want {
			// Fixed-point at 2^16: quantization error ≤ ~2^-15 per term.
			if math.Abs(got[i]-want[i]) > 1e-3 {
				t.Errorf("n=%d output %d: got %v want %v", n, i, got[i], want[i])
			}
		}
	}
}

// TestMPC_SharesAreUniform: any single share must carry no information — check
// the basic algebra: shares differ per invocation, and each share alone is not
// the fixed-point input.
func TestMPC_SharesAreUniform(t *testing.T) {
	x := []float64{3.25}
	s1, err := SplitShares(x, 3)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	s2, err := SplitShares(x, 3)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	// Fresh randomness each time (probability of collision ~2^-64).
	if s1[0][0] == s2[0][0] && s1[1][0] == s2[1][0] {
		t.Error("shares must be freshly random per invocation")
	}
	// Reconstruction holds.
	sum := s1[0][0] + s1[1][0] + s1[2][0]
	if int64(sum) != toFixed(3.25) {
		t.Errorf("shares must sum to the fixed-point input: %d != %d", int64(sum), toFixed(3.25))
	}
}

func TestMPC_SplitShareErrors(t *testing.T) {
	if _, err := SplitShares([]float64{1}, 1); err == nil {
		t.Error("single party must be rejected")
	}
	if _, err := SplitShares(nil, 3); err == nil {
		t.Error("empty input must be rejected")
	}
}

func TestMPC_ClusterConstructionErrors(t *testing.T) {
	if _, err := NewMPCCluster([]MPCParty{LocalParty{Name: "a"}}, false, "", ""); err == nil {
		t.Error("single-party cluster must be rejected")
	}
	if _, err := NewMPCCluster([]MPCParty{LocalParty{Name: "a"}, nil}, false, "", ""); err == nil {
		t.Error("nil party must be rejected")
	}
	if _, err := NewMPCCluster([]MPCParty{LocalParty{Name: ""}, LocalParty{Name: "b"}}, false, "", ""); err == nil {
		t.Error("unidentified party must be rejected")
	}
	if _, err := NewMPCCluster([]MPCParty{LocalParty{Name: "a"}, LocalParty{Name: "a"}}, false, "", ""); err == nil {
		t.Error("duplicate party ids must be rejected")
	}
}

func TestMPC_EvaluateErrors(t *testing.T) {
	cluster := mpcTestCluster(t, 3, true)
	model := fheTestModel()
	if err := cluster.RegisterModel(model); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := cluster.RegisterModel(LinearModel{ID: "bad"}); err == nil {
		t.Error("invalid model must be rejected at registration")
	}

	in, err := cluster.EncryptInput([]float64{1, 2, 3})
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	ctx := context.Background()

	if _, err := cluster.Evaluate(ctx, in, ModelRef{ModelID: "missing"}); err == nil {
		t.Error("unregistered model must be rejected")
	}
	if _, err := cluster.Evaluate(ctx, EncryptedInput("short"), ModelRef{ModelID: model.ID}); err == nil {
		t.Error("malformed bundle must be rejected")
	}

	// Bundle with the wrong party count.
	shares, _ := SplitShares([]float64{1, 2, 3}, 2)
	if _, err := cluster.Evaluate(ctx, marshalShareBundle(shares), ModelRef{ModelID: model.ID}); err == nil {
		t.Error("party-count mismatch must be rejected")
	}
	// Bundle with the wrong dimension.
	shares4, _ := SplitShares([]float64{1, 2, 3, 4}, 3)
	if _, err := cluster.Evaluate(ctx, marshalShareBundle(shares4), ModelRef{ModelID: model.ID}); err == nil {
		t.Error("dimension mismatch must be rejected")
	}
}

// erroringParty exercises party-failure propagation.
type erroringParty struct{ name string }

func (p erroringParty) ID() string { return p.name }
func (p erroringParty) ComputeLinear(context.Context, [][]int64, []uint64) ([]uint64, error) {
	return nil, fmt.Errorf("party %s unreachable", p.name)
}

// shortParty returns the wrong output arity.
type shortParty struct{ name string }

func (p shortParty) ID() string { return p.name }
func (p shortParty) ComputeLinear(context.Context, [][]int64, []uint64) ([]uint64, error) {
	return []uint64{1}, nil
}

func TestMPC_PartyFailures(t *testing.T) {
	model := fheTestModel()
	x := []float64{1, 2, 3}

	mk := func(second MPCParty) *MPCCluster {
		c, err := NewMPCCluster([]MPCParty{LocalParty{Name: "a"}, second}, true, "", "")
		if err != nil {
			t.Fatalf("cluster: %v", err)
		}
		if err := c.RegisterModel(model); err != nil {
			t.Fatalf("register: %v", err)
		}
		return c
	}

	c := mk(erroringParty{name: "b"})
	in, _ := c.EncryptInput(x)
	if _, err := c.Evaluate(context.Background(), in, ModelRef{ModelID: model.ID}); err == nil {
		t.Error("party error must propagate")
	}

	c = mk(shortParty{name: "b"})
	in, _ = c.EncryptInput(x)
	if _, err := c.Evaluate(context.Background(), in, ModelRef{ModelID: model.ID}); err == nil {
		t.Error("wrong output arity must be rejected")
	}
}

func TestMPC_LocalPartyErrors(t *testing.T) {
	p := LocalParty{Name: "a"}
	if _, err := p.ComputeLinear(context.Background(), nil, []uint64{1}); err == nil {
		t.Error("no weights must be rejected")
	}
	if _, err := p.ComputeLinear(context.Background(), [][]int64{{1, 2}}, []uint64{1}); err == nil {
		t.Error("row/share length mismatch must be rejected")
	}
}

func TestMPC_BackendHonesty(t *testing.T) {
	if _, err := NewMPCBackendWithCluster(nil); err == nil {
		t.Error("nil cluster must be rejected")
	}

	model := fheTestModel()
	run := func(colocated bool) ConfidentialityAttestation {
		cluster := mpcTestCluster(t, 3, colocated)
		if err := cluster.RegisterModel(model); err != nil {
			t.Fatalf("register: %v", err)
		}
		b, err := NewMPCBackendWithCluster(cluster)
		if err != nil {
			t.Fatalf("backend: %v", err)
		}
		if b.Kind() != BackendMPC || b.Available() != nil {
			t.Fatalf("backend surface wrong: kind=%q avail=%v", b.Kind(), b.Available())
		}
		if b.SatisfiesPlatform("amd-sev-snp") {
			t.Error("MPC must not claim a hardware platform")
		}
		sess, err := b.Prepare(context.Background(), ConfidentialityPolicy{})
		if err != nil {
			t.Fatalf("prepare: %v", err)
		}
		defer sess.Close()
		in, err := cluster.EncryptInput([]float64{1, 2, 3})
		if err != nil {
			t.Fatalf("share: %v", err)
		}
		out, att, err := b.Execute(context.Background(), sess, in, ModelRef{ModelID: model.ID})
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		sum := sha256.Sum256(out.Plaintext)
		if !bytesEqual(sum[:], out.OutputCommitment) {
			t.Error("output commitment must cover the revealed result")
		}
		if att.Backend != BackendMPC || att.Verification != VerificationNone {
			t.Errorf("attestation dims wrong: %+v", att)
		}
		if len(att.Measurement) == 0 {
			t.Error("measurement must commit to model + party count")
		}
		return att
	}

	// The core honesty gate: colocated clusters must NOT claim data sealing;
	// distributed clusters do.
	if att := run(true); att.DataSealed {
		t.Error("colocated cluster must not claim DataSealed")
	}
	if att := run(false); !att.DataSealed {
		t.Error("distributed cluster genuinely seals data")
	}

	// Execute error propagation.
	cluster := mpcTestCluster(t, 2, true)
	b, _ := NewMPCBackendWithCluster(cluster)
	if _, _, err := b.Execute(context.Background(), noopSession{}, EncryptedInput("x"), ModelRef{ModelID: "missing"}); err == nil {
		t.Error("cluster error must propagate through the backend")
	}
}

func TestMPC_BundleWireErrors(t *testing.T) {
	if _, err := unmarshalShareBundle([]byte{1}); err == nil {
		t.Error("short bundle must be rejected")
	}
	// Bad version.
	shares, _ := SplitShares([]float64{1}, 2)
	good := marshalShareBundle(shares)
	bad := append([]byte{}, good...)
	bad[3] = 99
	if _, err := unmarshalShareBundle(bad); err == nil {
		t.Error("unknown version must be rejected")
	}
	// Implausible shape.
	bad = append([]byte{}, good...)
	bad[7] = 0 // n = 0
	if _, err := unmarshalShareBundle(bad); err == nil {
		t.Error("implausible shape must be rejected")
	}
	// Length/shape mismatch.
	if _, err := unmarshalShareBundle(good[:len(good)-8]); err == nil {
		t.Error("truncated payload must be rejected")
	}
}
