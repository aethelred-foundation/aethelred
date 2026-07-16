package confidential

import (
	"context"
	"crypto/sha256"
	"math"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// fheTestModel: 2 outputs, 3 inputs — small but genuinely affine.
func fheTestModel() LinearModel {
	return LinearModel{
		ID:      "risk-score-v1",
		Weights: [][]float64{{0.5, -1.25, 2.0}, {1.0, 0.75, -0.5}},
		Bias:    []float64{0.25, -1.0},
	}
}

func newFHEPair(t *testing.T) (*FHEClient, *FHEEngine) {
	t.Helper()
	client, err := NewFHEClient(8)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	engine, err := NewFHEEngine(client.EvaluationKeys())
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return client, engine
}

// TestFHE_RoundTrip is the proof the backend is REAL homomorphic encryption:
// the engine computes y = W·x + b on a ciphertext it cannot decrypt, and the
// key-holding client recovers the correct result within CKKS precision.
func TestFHE_RoundTrip(t *testing.T) {
	client, engine := newFHEPair(t)
	model := fheTestModel()
	if err := engine.RegisterModel(model); err != nil {
		t.Fatalf("register: %v", err)
	}

	x := []float64{1.5, -2.0, 0.75}
	want, err := model.Apply(x)
	if err != nil {
		t.Fatalf("plaintext apply: %v", err)
	}

	ctIn, err := client.Encrypt(x)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	backend, err := NewFHEBackendWithEngine(engine, "EU", "fhe-worker-1")
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	sess, err := backend.Prepare(context.Background(), ConfidentialityPolicy{})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer sess.Close()

	out, att, err := backend.Execute(context.Background(), sess, ctIn, ModelRef{ModelID: model.ID, ModelHash: model.Hash()})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	got, err := client.Decrypt(out)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d outputs, want %d", len(got), len(want))
	}
	for i := range want {
		if math.Abs(got[i]-want[i]) > 1e-3 {
			t.Errorf("output %d: got %v, want %v (|Δ|=%.2e)", i, got[i], want[i], math.Abs(got[i]-want[i]))
		}
	}

	// The attestation must make honest claims.
	if att.Backend != BackendFHE {
		t.Errorf("backend = %q", att.Backend)
	}
	if att.Verification != VerificationNone {
		t.Errorf("FHE must not claim a verification method, got %q", att.Verification)
	}
	if att.Platform != "" || att.TrustBasis != "" {
		t.Errorf("FHE must not claim hardware attestation: platform=%q basis=%q", att.Platform, att.TrustBasis)
	}
	if !att.DataSealed {
		t.Error("FHE genuinely seals data — DataSealed must be true")
	}
	if len(att.Measurement) == 0 {
		t.Error("measurement (params+model hash) must be set")
	}
	if att.Jurisdiction != "EU" || att.Worker != "fhe-worker-1" {
		t.Errorf("deployment fields wrong: %+v", att)
	}

	// Output commitment must cover the returned ciphertext bytes.
	sum := sha256.Sum256(out.Plaintext)
	if !bytesEqual(sum[:], out.OutputCommitment) {
		t.Error("output commitment does not match returned ciphertexts")
	}
}

func TestFHE_ClientConstructionErrors(t *testing.T) {
	if _, err := NewFHEClient(0); err == nil {
		t.Error("maxDim 0 must be rejected")
	}
	if _, err := NewFHEClient(1 << 20); err == nil {
		t.Error("maxDim beyond slot capacity must be rejected")
	}
}

func TestFHE_EncryptErrors(t *testing.T) {
	client, _ := newFHEPair(t)
	if _, err := client.Encrypt(nil); err == nil {
		t.Error("empty input must be rejected")
	}
	big := make([]float64, client.params.MaxSlots())
	if _, err := client.Encrypt(big); err == nil {
		t.Error("input beyond slot capacity must be rejected")
	}
}

func TestFHE_EngineConstructionAndRegistration(t *testing.T) {
	if _, err := NewFHEEngine(nil); err == nil {
		t.Error("nil evaluation keys must be rejected")
	}
	_, engine := newFHEPair(t)
	if err := engine.RegisterModel(LinearModel{ID: "bad"}); err == nil {
		t.Error("invalid model must be rejected")
	}
	huge := LinearModel{
		ID:      "huge",
		Weights: [][]float64{make([]float64, engine.params.MaxSlots())},
		Bias:    []float64{0},
	}
	if err := engine.RegisterModel(huge); err == nil {
		t.Error("model beyond slot capacity must be rejected")
	}
}

func TestFHE_EvaluateErrors(t *testing.T) {
	client, engine := newFHEPair(t)
	model := fheTestModel()
	if err := engine.RegisterModel(model); err != nil {
		t.Fatalf("register: %v", err)
	}
	ctIn, err := client.Encrypt([]float64{1, 2, 3})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Unregistered model.
	if _, _, err := engine.Evaluate(ctIn, ModelRef{ModelID: "nope"}); err == nil {
		t.Error("unregistered model must be rejected")
	}
	// Hash mismatch: ref commits to different weights.
	if _, _, err := engine.Evaluate(ctIn, ModelRef{ModelID: model.ID, ModelHash: []byte("wrong")}); err == nil {
		t.Error("model hash mismatch must be rejected")
	}
	// Garbage ciphertext.
	if _, _, err := engine.Evaluate(EncryptedInput("not-a-ciphertext"), ModelRef{ModelID: model.ID}); err == nil {
		t.Error("malformed ciphertext must be rejected")
	}

	// White-box: a model whose row exceeds slot capacity bypassing RegisterModel
	// must fail at encode time (defense in depth).
	engine.models["oversize"] = LinearModel{
		ID:      "oversize",
		Weights: [][]float64{make([]float64, engine.params.MaxSlots()+1)},
		Bias:    []float64{0},
	}
	if _, _, err := engine.Evaluate(ctIn, ModelRef{ModelID: "oversize"}); err == nil {
		t.Error("oversize row must fail at homomorphic encode")
	}

	// White-box: degree-2 ciphertext (never produced by the client) must be
	// rejected by the multiply.
	deg2 := rlwe.NewCiphertext(engine.params, 2, engine.params.MaxLevel())
	deg2Bytes, err := deg2.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal deg2: %v", err)
	}
	if _, _, err := engine.Evaluate(deg2Bytes, ModelRef{ModelID: model.ID}); err == nil {
		t.Error("degree-2 input ciphertext must be rejected")
	}

	// White-box: a level-0 ciphertext leaves no level to rescale into.
	ct := new(rlwe.Ciphertext)
	if err := ct.UnmarshalBinary(ctIn); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	lvl0 := engine.evaluator.DropLevelNew(ct, ct.Level())
	lvl0Bytes, err := lvl0.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal lvl0: %v", err)
	}
	if _, _, err := engine.Evaluate(lvl0Bytes, ModelRef{ModelID: model.ID}); err == nil {
		t.Error("level-0 input ciphertext must be rejected at rescale")
	}
}

func TestFHE_DecryptAndFrameErrors(t *testing.T) {
	client, _ := newFHEPair(t)

	// Commitment mismatch.
	if _, err := client.Decrypt(Output{Plaintext: []byte{1, 2, 3, 4}, OutputCommitment: []byte("bad")}); err == nil {
		t.Error("commitment mismatch must be rejected")
	}
	// Truncated header (no commitment → skips the hash check).
	if _, err := readCiphertextFrames([]byte{0, 0}, nil); err == nil {
		t.Error("truncated frame header must be rejected")
	}
	// Truncated body.
	if _, err := readCiphertextFrames([]byte{0, 0, 0, 9, 1, 2}, nil); err == nil {
		t.Error("truncated frame body must be rejected")
	}
	// Valid framing, garbage ciphertext bytes.
	bad := appendFrame(nil, []byte("garbage-ciphertext"))
	if _, err := readCiphertextFrames(bad, nil); err == nil {
		t.Error("malformed ciphertext frame must be rejected")
	}
	// Empty bundle.
	if _, err := readCiphertextFrames(nil, nil); err == nil {
		t.Error("empty output must be rejected")
	}
}

func TestFHE_BackendSurface(t *testing.T) {
	if _, err := NewFHEBackendWithEngine(nil, "", ""); err == nil {
		t.Error("nil engine must be rejected")
	}
	_, engine := newFHEPair(t)
	b, err := NewFHEBackendWithEngine(engine, "EU", "w")
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	if b.Kind() != BackendFHE {
		t.Errorf("kind = %q", b.Kind())
	}
	if b.Available() != nil {
		t.Error("engine-backed FHE must be available")
	}
	// FHE attests no hardware platform — pinned-platform policies fail closed.
	if b.SatisfiesPlatform("amd-sev-snp") || b.SatisfiesPlatform("nvidia-gpu") {
		t.Error("FHE must not claim any hardware platform")
	}
	// Execute error propagation (unregistered model).
	sess, err := b.Prepare(context.Background(), ConfidentialityPolicy{})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, _, err := b.Execute(context.Background(), sess, EncryptedInput("x"), ModelRef{ModelID: "missing"}); err == nil {
		t.Error("engine error must propagate through the backend")
	}
}

// TestFHE_RegistrySelectsStrongest: with a real FHE backend registered, an
// unrestricted policy deterministically selects FHE (strength 3 > TEE 1) — and
// an FHE-only policy is now genuinely satisfiable.
func TestFHE_RegistrySelectsStrongest(t *testing.T) {
	_, engine := newFHEPair(t)
	fhe, err := NewFHEBackendWithEngine(engine, "EU", "w")
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	r := NewRegistry()
	r.Register(NewTEEBackend(nil))
	r.Register(fhe)

	b, err := r.Select(ConfidentialityPolicy{})
	if err != nil || b.Kind() != BackendFHE {
		t.Fatalf("expected FHE selected (strongest), got %v err=%v", b, err)
	}
	b, err = r.Select(ConfidentialityPolicy{AllowedBackends: []Backend{BackendFHE}})
	if err != nil || b.Kind() != BackendFHE {
		t.Fatalf("FHE-only policy must now be satisfiable, got %v err=%v", b, err)
	}
	b, err = r.Select(ConfidentialityPolicy{AllowedBackends: []Backend{BackendTEE}})
	if err != nil || b.Kind() != BackendTEE {
		t.Fatalf("TEE-only policy must still select TEE, got %v err=%v", b, err)
	}
}

func TestFHE_ParamsHashStable(t *testing.T) {
	p1, err := ckks.NewParametersFromLiteral(fheParametersLiteral())
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	p2, err := ckks.NewParametersFromLiteral(fheParametersLiteral())
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	if !bytesEqual(fheParamsHash(p1), fheParamsHash(p2)) {
		t.Error("params hash must be deterministic")
	}
	if len(fheParamsHash(p1)) != sha256.Size {
		t.Error("params hash must be sha256")
	}
}
