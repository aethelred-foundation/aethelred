package verify

import (
	"context"
	"math"
	"strings"
	"testing"

	"cosmossdk.io/log"

	"github.com/aethelred/aethelred/internal/confidential"
)

func newConfidentialOrchestrator(t *testing.T) *VerificationOrchestrator {
	t.Helper()
	return NewVerificationOrchestrator(log.NewNopLogger(), DefaultOrchestratorConfig())
}

func testLinearModel() confidential.LinearModel {
	return confidential.LinearModel{
		ID:      "risk-score-v1",
		Weights: [][]float64{{0.5, -1.25, 2.0}, {1.0, 0.75, -0.5}},
		Bias:    []float64{0.25, -1.0},
	}
}

// TestExecuteConfidential_FHEEndToEnd drives the WHOLE worker path: policy →
// registry select → FHE engine executes on ciphertext → policy hash bound →
// pre-flight passes → the key-holding client decrypts the correct result.
func TestExecuteConfidential_FHEEndToEnd(t *testing.T) {
	client, err := confidential.NewFHEClient(8)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	engine, err := confidential.NewFHEEngine(client.EvaluationKeys())
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	model := testLinearModel()
	if err := engine.RegisterModel(model); err != nil {
		t.Fatalf("register: %v", err)
	}
	fhe, err := confidential.NewFHEBackendWithEngine(engine, "EU", "worker-1")
	if err != nil {
		t.Fatalf("backend: %v", err)
	}

	vo := newConfidentialOrchestrator(t)
	r := confidential.NewRegistry()
	r.Register(fhe)
	vo.SetConfidentialRegistry(r)

	if got := vo.ConfidentialBackendsAvailable(); len(got) != 1 || got[0] != confidential.BackendFHE {
		t.Fatalf("available backends = %v, want [fhe]", got)
	}

	x := []float64{1.5, -2.0, 0.75}
	want, err := model.Apply(x)
	if err != nil {
		t.Fatalf("plaintext apply: %v", err)
	}
	in, err := client.Encrypt(x)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	policy := confidential.ConfidentialityPolicy{
		AllowedBackends: []confidential.Backend{confidential.BackendFHE},
		DataResidency:   []confidential.Jurisdiction{"EU"},
	}
	res, err := vo.ExecuteConfidential(context.Background(), policy, in, confidential.ModelRef{ModelID: model.ID, ModelHash: model.Hash()})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	if res.AttestationType != "fhe" {
		t.Errorf("wire signal = %q, want fhe", res.AttestationType)
	}
	if res.Attestation.Backend != confidential.BackendFHE || !res.Attestation.DataSealed {
		t.Errorf("attestation wrong: %+v", res.Attestation)
	}
	if len(res.Attestation.PolicyHash) == 0 {
		t.Error("policy hash must be bound to the attestation")
	}

	got, err := client.Decrypt(res.Output)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	for i := range want {
		if math.Abs(got[i]-want[i]) > 1e-3 {
			t.Errorf("output %d: got %v want %v", i, got[i], want[i])
		}
	}

	// Metrics counted the execution.
	if vo.GetMetrics().ConfidentialExecutions != 1 {
		t.Error("confidential execution not counted")
	}
}

// TestExecuteConfidential_ColocatedMPCPreFlightRejected is the honesty gate in
// action: a colocated cluster runs the real protocol but yields
// DataSealed=false, so a policy demanding MPC confidentiality fails PRE-FLIGHT
// — the worker never submits a result consensus would reject.
func TestExecuteConfidential_ColocatedMPCPreFlightRejected(t *testing.T) {
	model := testLinearModel()

	mkCluster := func(colocated bool) (*confidential.MPCCluster, confidential.ConfidentialBackend) {
		parties := []confidential.MPCParty{
			confidential.LocalParty{Name: "op-a"},
			confidential.LocalParty{Name: "op-b"},
			confidential.LocalParty{Name: "op-c"},
		}
		cluster, err := confidential.NewMPCCluster(parties, colocated, "EU", "coordinator")
		if err != nil {
			t.Fatalf("cluster: %v", err)
		}
		if err := cluster.RegisterModel(model); err != nil {
			t.Fatalf("register: %v", err)
		}
		b, err := confidential.NewMPCBackendWithCluster(cluster)
		if err != nil {
			t.Fatalf("backend: %v", err)
		}
		return cluster, b
	}

	policy := confidential.ConfidentialityPolicy{
		AllowedBackends: []confidential.Backend{confidential.BackendMPC},
	}

	// Colocated: protocol runs, confidentiality claim fails pre-flight.
	cluster, backend := mkCluster(true)
	vo := newConfidentialOrchestrator(t)
	r := confidential.NewRegistry()
	r.Register(backend)
	vo.SetConfidentialRegistry(r)

	in, err := cluster.EncryptInput([]float64{1, 2, 3})
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	_, err = vo.ExecuteConfidential(context.Background(), policy, in, confidential.ModelRef{ModelID: model.ID})
	if err == nil {
		t.Fatal("colocated MPC against a sealing policy must fail pre-flight")
	}
	if want := "pre-flight"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q must mention %q", err.Error(), want)
	}

	// Distributed: same protocol, honest claim, succeeds with signal "mpc".
	cluster, backend = mkCluster(false)
	vo = newConfidentialOrchestrator(t)
	r = confidential.NewRegistry()
	r.Register(backend)
	vo.SetConfidentialRegistry(r)

	in, err = cluster.EncryptInput([]float64{1, 2, 3})
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	res, err := vo.ExecuteConfidential(context.Background(), policy, in, confidential.ModelRef{ModelID: model.ID})
	if err != nil {
		t.Fatalf("distributed MPC must succeed: %v", err)
	}
	if res.AttestationType != "mpc" || !res.Attestation.DataSealed {
		t.Errorf("distributed MPC result wrong: signal=%q att=%+v", res.AttestationType, res.Attestation)
	}
}

func TestExecuteConfidential_ConfigurationErrors(t *testing.T) {
	vo := newConfidentialOrchestrator(t)

	// No registry installed.
	if _, err := vo.ExecuteConfidential(context.Background(), confidential.ConfidentialityPolicy{}, nil, confidential.ModelRef{}); err == nil {
		t.Error("missing registry must error")
	}
	if vo.ConfidentialBackendsAvailable() != nil {
		t.Error("no registry must advertise no backends")
	}

	// Registry with no backend satisfying the policy.
	r := confidential.NewRegistry()
	vo.SetConfidentialRegistry(r)
	if _, err := vo.ExecuteConfidential(context.Background(), confidential.ConfidentialityPolicy{}, nil, confidential.ModelRef{}); err == nil {
		t.Error("empty registry must error at selection")
	}

	// Backend selected but execution fails (unregistered model).
	client, err := confidential.NewFHEClient(4)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	engine, err := confidential.NewFHEEngine(client.EvaluationKeys())
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	fhe, err := confidential.NewFHEBackendWithEngine(engine, "EU", "w")
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	r.Register(fhe)
	if _, err := vo.ExecuteConfidential(context.Background(), confidential.ConfidentialityPolicy{}, confidential.EncryptedInput("x"), confidential.ModelRef{ModelID: "missing"}); err == nil {
		t.Error("execution failure must propagate")
	}
}

// prepFailBackend is available but fails at session preparation — exercises
// the Prepare error path of ExecuteConfidential.
type prepFailBackend struct{}

func (prepFailBackend) Kind() confidential.Backend        { return confidential.BackendTEE }
func (prepFailBackend) Available() error                  { return nil }
func (prepFailBackend) SatisfiesPlatform(confidential.Platform) bool { return true }
func (prepFailBackend) Prepare(context.Context, confidential.ConfidentialityPolicy) (confidential.Session, error) {
	return nil, context.DeadlineExceeded
}
func (prepFailBackend) Execute(context.Context, confidential.Session, confidential.EncryptedInput, confidential.ModelRef) (confidential.Output, confidential.ConfidentialityAttestation, error) {
	return confidential.Output{}, confidential.ConfidentialityAttestation{}, nil
}

func TestExecuteConfidential_PrepareFailure(t *testing.T) {
	vo := newConfidentialOrchestrator(t)
	r := confidential.NewRegistry()
	r.Register(prepFailBackend{})
	vo.SetConfidentialRegistry(r)

	_, err := vo.ExecuteConfidential(context.Background(), confidential.ConfidentialityPolicy{}, nil, confidential.ModelRef{})
	if err == nil || !strings.Contains(err.Error(), "session") {
		t.Errorf("prepare failure must surface as a session error, got %v", err)
	}
}

func TestWireSignalForBackend(t *testing.T) {
	cases := map[confidential.Backend]string{
		confidential.BackendTEE:    "tee",
		confidential.BackendGPUCC:  "gpu-cc",
		confidential.BackendMPC:    "mpc",
		confidential.BackendFHE:    "fhe",
		confidential.BackendHybrid: "hybrid",
		confidential.BackendNone:   "",
		confidential.Backend("x"):  "",
	}
	for b, want := range cases {
		if got := WireSignalForBackend(b); got != want {
			t.Errorf("WireSignalForBackend(%q) = %q, want %q", b, got, want)
		}
	}
}

