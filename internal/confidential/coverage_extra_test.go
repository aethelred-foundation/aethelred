package confidential

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// TestFHE_EvaluateWithoutGaloisKeys: an engine built from an evaluation-key set
// missing the inner-sum Galois keys must fail at the rotation step — proving
// the engine really performs key-switched rotations (no keys, no computation).
func TestFHE_EvaluateWithoutGaloisKeys(t *testing.T) {
	client, err := NewFHEClient(8)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	// Empty key set: no relinearization key, no Galois keys.
	engine, err := NewFHEEngine(rlwe.NewMemEvaluationKeySet(nil))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	model := fheTestModel()
	if err := engine.RegisterModel(model); err != nil {
		t.Fatalf("register: %v", err)
	}
	ctIn, err := client.Encrypt([]float64{1, 2, 3})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, _, err := engine.Evaluate(ctIn, ModelRef{ModelID: model.ID}); err == nil {
		t.Error("evaluation without Galois keys must fail at the inner-sum")
	}
}

// TestFHE_SafeUnmarshalErrorPath: some malformed inputs make lattigo return a
// plain error rather than panicking; both must surface as errors.
func TestFHE_SafeUnmarshalErrorPath(t *testing.T) {
	if _, err := safeUnmarshalCiphertext(nil); err == nil {
		t.Error("empty ciphertext must be rejected")
	}
	if _, err := safeUnmarshalCiphertext([]byte{0x01}); err == nil {
		t.Error("one-byte ciphertext must be rejected")
	}
}

func TestMPC_EncryptInputEmpty(t *testing.T) {
	cluster := mpcTestCluster(t, 2, true)
	if _, err := cluster.EncryptInput(nil); err == nil {
		t.Error("empty input must be rejected")
	}
}

// fakeNvidiaSMI installs a stub nvidia-smi at the front of PATH so every branch
// of the production detector is exercised without CC hardware.
func fakeNvidiaSMI(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "nvidia-smi")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestDetectNVIDIACC_AllBranches(t *testing.T) {
	t.Run("missing binary", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir()) // no nvidia-smi anywhere
		if err := DetectNVIDIACC(); err == nil {
			t.Error("missing nvidia-smi must be an error")
		}
	})
	t.Run("command fails", func(t *testing.T) {
		fakeNvidiaSMI(t, `echo "ERR: unsupported"; exit 1`)
		if err := DetectNVIDIACC(); err == nil {
			t.Error("failing nvidia-smi must be an error")
		}
	})
	t.Run("not ready", func(t *testing.T) {
		fakeNvidiaSMI(t, `echo "Confidential Compute GPUs Ready state: not ready"`)
		if err := DetectNVIDIACC(); err == nil {
			t.Error("not-ready state must be an error")
		}
	})
	t.Run("no cc mention", func(t *testing.T) {
		fakeNvidiaSMI(t, `echo "Driver Version: 550.00"`)
		if err := DetectNVIDIACC(); err == nil {
			t.Error("output without readiness must be an error")
		}
	})
	t.Run("ready", func(t *testing.T) {
		fakeNvidiaSMI(t, `echo "Confidential Compute GPUs Ready state: ready"`)
		if err := DetectNVIDIACC(); err != nil {
			t.Errorf("ready state must pass: %v", err)
		}
	})
}
