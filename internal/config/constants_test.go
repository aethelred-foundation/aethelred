package config

import (
	"testing"
	"time"
)

func TestDefaultHTTPConfig(t *testing.T) {
	t.Parallel()
	cfg := DefaultHTTPConfig()
	if cfg.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", cfg.Timeout)
	}
	if cfg.MaxResponseSize != 10*1024*1024 {
		t.Errorf("expected 10MB max response, got %d", cfg.MaxResponseSize)
	}
	if cfg.MaxIdleConns != 10 {
		t.Errorf("expected 10 idle conns, got %d", cfg.MaxIdleConns)
	}
	if cfg.IdleConnTimeout != 90*time.Second {
		t.Errorf("expected 90s idle timeout, got %v", cfg.IdleConnTimeout)
	}
	if cfg.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("expected 10s TLS timeout, got %v", cfg.TLSHandshakeTimeout)
	}
	if cfg.MinTLSVersion != 0x0303 {
		t.Errorf("expected TLS 1.2 (0x0303), got 0x%04x", cfg.MinTLSVersion)
	}
}

func TestDefaultProofLimits(t *testing.T) {
	t.Parallel()
	pl := DefaultProofLimits()
	if pl.Groth16MinSize != 192 {
		t.Errorf("expected Groth16MinSize=192, got %d", pl.Groth16MinSize)
	}
	if pl.EZKLMinSize != 256 {
		t.Errorf("expected EZKLMinSize=256, got %d", pl.EZKLMinSize)
	}
	if pl.Halo2MinSize != 384 {
		t.Errorf("expected Halo2MinSize=384, got %d", pl.Halo2MinSize)
	}
	if pl.MaxVerifyingKeySize != 10*1024*1024 {
		t.Errorf("expected 10MB max VK size, got %d", pl.MaxVerifyingKeySize)
	}
	if pl.MaxPublicInputs != 1024 {
		t.Errorf("expected 1024 max public inputs, got %d", pl.MaxPublicInputs)
	}
}

func TestGetMinProofSize(t *testing.T) {
	t.Parallel()
	pl := DefaultProofLimits()
	tests := []struct {
		system string
		want   int
	}{
		{"groth16", 192},
		{"ezkl", 256},
		{"halo2", 384},
		{"plonky2", 256},
		{"risc0", 512},
		{"stark", 1024},
		{"unknown", 128},
		{"", 128},
	}
	for _, tt := range tests {
		t.Run(tt.system, func(t *testing.T) {
			t.Parallel()
			if got := pl.GetMinProofSize(tt.system); got != tt.want {
				t.Errorf("GetMinProofSize(%q) = %d, want %d", tt.system, got, tt.want)
			}
		})
	}
}

func TestDefaultTEEConfig(t *testing.T) {
	t.Parallel()
	cfg := DefaultTEEConfig()
	if cfg.SGXMinQuoteSize != 432 {
		t.Errorf("expected SGXMinQuoteSize=432, got %d", cfg.SGXMinQuoteSize)
	}
	if cfg.TDXMinQuoteSize != 584 {
		t.Errorf("expected TDXMinQuoteSize=584, got %d", cfg.TDXMinQuoteSize)
	}
	if cfg.SEVMinReportSize != 672 {
		t.Errorf("expected SEVMinReportSize=672, got %d", cfg.SEVMinReportSize)
	}
	if cfg.MaxQuoteAge != 5*time.Minute {
		t.Errorf("expected 5min max quote age, got %v", cfg.MaxQuoteAge)
	}
	if cfg.DefaultMREnclaveLen != 32 {
		t.Errorf("expected MREnclave len 32, got %d", cfg.DefaultMREnclaveLen)
	}
}

func TestDefaultCircuitBreakerConfig(t *testing.T) {
	t.Parallel()
	cfg := DefaultCircuitBreakerConfig()
	if cfg.FailureThreshold != 5 {
		t.Errorf("expected threshold=5, got %d", cfg.FailureThreshold)
	}
	if cfg.SuccessThreshold != 3 {
		t.Errorf("expected success threshold=3, got %d", cfg.SuccessThreshold)
	}
	if cfg.HalfOpenTimeout != 30*time.Second {
		t.Errorf("expected 30s half-open timeout, got %v", cfg.HalfOpenTimeout)
	}
	if cfg.OpenTimeout != 60*time.Second {
		t.Errorf("expected 60s open timeout, got %v", cfg.OpenTimeout)
	}
	if cfg.MaxConcurrent != 1 {
		t.Errorf("expected 1 max concurrent, got %d", cfg.MaxConcurrent)
	}
}

func TestDefaultVerificationTimeouts(t *testing.T) {
	t.Parallel()
	vt := DefaultVerificationTimeouts()
	if vt.ZKProofTimeout != 5*time.Second {
		t.Errorf("expected 5s ZK proof timeout, got %v", vt.ZKProofTimeout)
	}
	if vt.TEEAttestationTimeout != 10*time.Second {
		t.Errorf("expected 10s TEE timeout, got %v", vt.TEEAttestationTimeout)
	}
	if vt.SignatureTimeout != 1*time.Second {
		t.Errorf("expected 1s signature timeout, got %v", vt.SignatureTimeout)
	}
	if vt.HashTimeout != 5*time.Second {
		t.Errorf("expected 5s hash timeout, got %v", vt.HashTimeout)
	}
}

func TestDefaultJobLimits(t *testing.T) {
	t.Parallel()
	jl := DefaultJobLimits()
	if jl.MaxPendingJobs != 1000 {
		t.Errorf("expected 1000 max pending, got %d", jl.MaxPendingJobs)
	}
	if jl.MaxJobExpiry != 100800 {
		t.Errorf("expected 100800 max expiry, got %d", jl.MaxJobExpiry)
	}
	if jl.DefaultJobExpiry != 14400 {
		t.Errorf("expected 14400 default expiry, got %d", jl.DefaultJobExpiry)
	}
	if jl.MaxInputSize != 1*1024*1024 {
		t.Errorf("expected 1MB max input, got %d", jl.MaxInputSize)
	}
	if jl.MaxOutputSize != 10*1024*1024 {
		t.Errorf("expected 10MB max output, got %d", jl.MaxOutputSize)
	}
	if jl.MaxVerificationResults != 100 {
		t.Errorf("expected 100 max results, got %d", jl.MaxVerificationResults)
	}
}

func TestDefaultCryptoParams(t *testing.T) {
	t.Parallel()
	cp := DefaultCryptoParams()
	if cp.Dilithium3PubKeySize != 1952 {
		t.Errorf("expected 1952, got %d", cp.Dilithium3PubKeySize)
	}
	if cp.Dilithium3SigSize != 3293 {
		t.Errorf("expected 3293, got %d", cp.Dilithium3SigSize)
	}
	if cp.ECDSASecp256k1PubKeySize != 33 {
		t.Errorf("expected 33, got %d", cp.ECDSASecp256k1PubKeySize)
	}
	if cp.SHA256Size != 32 {
		t.Errorf("expected 32, got %d", cp.SHA256Size)
	}
}

func TestDefaultNetworkConfig(t *testing.T) {
	t.Parallel()
	nc := DefaultNetworkConfig()
	if nc.DefaultRPCTimeout != 10*time.Second {
		t.Errorf("expected 10s RPC timeout, got %v", nc.DefaultRPCTimeout)
	}
	if nc.MaxPeers != 50 {
		t.Errorf("expected 50 max peers, got %d", nc.MaxPeers)
	}
	if nc.BlockTime != 6*time.Second {
		t.Errorf("expected 6s block time, got %v", nc.BlockTime)
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	if cfg.HTTP.Timeout != 30*time.Second {
		t.Error("HTTP timeout mismatch in aggregate config")
	}
	if cfg.Proof.Groth16MinSize != 192 {
		t.Error("Proof limits mismatch in aggregate config")
	}
	if cfg.TEE.SGXMinQuoteSize != 432 {
		t.Error("TEE config mismatch in aggregate config")
	}
	if cfg.CircuitBreaker.FailureThreshold != 5 {
		t.Error("CB config mismatch in aggregate config")
	}
	if cfg.Verification.ZKProofTimeout != 5*time.Second {
		t.Error("Verification config mismatch in aggregate config")
	}
	if cfg.Jobs.MaxPendingJobs != 1000 {
		t.Error("Jobs config mismatch in aggregate config")
	}
	if cfg.Crypto.SHA256Size != 32 {
		t.Error("Crypto config mismatch in aggregate config")
	}
	if cfg.Network.MaxPeers != 50 {
		t.Error("Network config mismatch in aggregate config")
	}
}

func TestGlobal(t *testing.T) {
	// Verify Global is initialized to defaults
	if Global.HTTP.Timeout != 30*time.Second {
		t.Error("Global config not initialized to defaults")
	}
}
