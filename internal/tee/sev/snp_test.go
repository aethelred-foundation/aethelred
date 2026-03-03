package sev

import (
	"testing"
)

func TestDefaultSNPVMConfig(t *testing.T) {
	t.Parallel()
	cfg := DefaultSNPVMConfig()
	if cfg.MemoryMB != 4096 {
		t.Errorf("expected 4096MB, got %d", cfg.MemoryMB)
	}
	if cfg.NumCPUs != 4 {
		t.Errorf("expected 4 CPUs, got %d", cfg.NumCPUs)
	}
	if !cfg.Policy.SMT {
		t.Error("expected SMT=true")
	}
	if cfg.Policy.Debug {
		t.Error("expected Debug=false")
	}
	if !cfg.Policy.VMPLRequired {
		t.Error("expected VMPLRequired=true")
	}
}

func TestNewSNPVM(t *testing.T) {
	t.Parallel()
	vm, err := NewSNPVM(nil)
	if err != nil {
		t.Fatalf("NewSNPVM() error: %v", err)
	}
	if vm == nil {
		t.Fatal("vm is nil")
	}
	if !vm.running {
		t.Error("vm should be running after init")
	}
}

func TestNewSNPVM_CustomConfig(t *testing.T) {
	t.Parallel()
	cfg := &SNPVMConfig{
		VMID:     "test-vm",
		MemoryMB: 8192,
		NumCPUs:  8,
		Policy: GuestPolicy{
			ABIMajor:     1,
			VMPLRequired: true,
		},
	}
	vm, err := NewSNPVM(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if vm.vmID != "test-vm" {
		t.Errorf("expected vmID 'test-vm', got %q", vm.vmID)
	}
}

func TestSNPVM_Execute(t *testing.T) {
	t.Parallel()
	vm, _ := NewSNPVM(nil)

	tests := []struct {
		op    string
		input []byte
	}{
		{"hash", []byte("test data")},
		{"verify", []byte("verify data")},
		{"inference", []byte("model input")},
		{"unknown", []byte("raw data")},
	}

	for _, tt := range tests {
		t.Run(tt.op, func(t *testing.T) {
			output, err := vm.Execute(tt.op, tt.input)
			if err != nil {
				t.Fatalf("Execute(%q) error: %v", tt.op, err)
			}
			if len(output) == 0 {
				t.Error("output should not be empty")
			}
		})
	}
}

func TestSNPVM_Execute_NotRunning(t *testing.T) {
	t.Parallel()
	vm, _ := NewSNPVM(nil)
	vm.Stop()
	_, err := vm.Execute("hash", []byte("data"))
	if err == nil {
		t.Error("expected error when VM not running")
	}
}

func TestSNPVM_GetAttestationReport(t *testing.T) {
	t.Parallel()
	vm, _ := NewSNPVM(nil)
	var reportData [SNPReportDataSize]byte
	copy(reportData[:], []byte("custom report data"))

	report, err := vm.GetAttestationReport(reportData)
	if err != nil {
		t.Fatalf("GetAttestationReport() error: %v", err)
	}
	if report.Version != 2 {
		t.Errorf("expected version 2, got %d", report.Version)
	}
	if report.ReportData != reportData {
		t.Error("report data mismatch")
	}
	if !report.PlatformInfo.SNPEnabled {
		t.Error("expected SNP enabled")
	}
}

func TestSNPVM_GetAttestationReport_NotRunning(t *testing.T) {
	t.Parallel()
	vm, _ := NewSNPVM(nil)
	vm.Stop()
	_, err := vm.GetAttestationReport([SNPReportDataSize]byte{})
	if err == nil {
		t.Error("expected error when VM not running")
	}
}

func TestSNPVM_GetMeasurement(t *testing.T) {
	t.Parallel()
	vm, _ := NewSNPVM(nil)
	m := vm.GetMeasurement()
	if len(m) == 0 {
		t.Error("measurement should not be empty")
	}
	// Should be hex-encoded 48 bytes = 96 chars
	if len(m) != 96 {
		t.Errorf("expected 96 hex chars, got %d", len(m))
	}
}

func TestSNPVM_GetExecutionLog(t *testing.T) {
	t.Parallel()
	vm, _ := NewSNPVM(nil)
	vm.Execute("hash", []byte("data1"))
	vm.Execute("verify", []byte("data2"))

	log := vm.GetExecutionLog()
	if len(log) != 2 {
		t.Errorf("expected 2 log entries, got %d", len(log))
	}
	if log[0].Operation != "hash" {
		t.Errorf("expected first op 'hash', got %q", log[0].Operation)
	}
}

func TestSNPVM_Stop(t *testing.T) {
	t.Parallel()
	vm, _ := NewSNPVM(nil)
	err := vm.Stop()
	if err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if vm.running {
		t.Error("VM should not be running after stop")
	}
}

func TestSNPVM_Destroy(t *testing.T) {
	t.Parallel()
	vm, _ := NewSNPVM(nil)
	vm.Execute("hash", []byte("data"))
	err := vm.Destroy()
	if err != nil {
		t.Fatalf("Destroy() error: %v", err)
	}
	if vm.running {
		t.Error("VM should not be running after destroy")
	}
	if vm.execLog != nil {
		t.Error("exec log should be nil after destroy")
	}
}

func TestSNPReportVerifier_VerifyReport_Valid(t *testing.T) {
	t.Parallel()
	vm, _ := NewSNPVM(nil)
	report, _ := vm.GetAttestationReport([SNPReportDataSize]byte{})

	verifier := NewSNPReportVerifier()
	result, err := verifier.VerifyReport(report)
	if err != nil {
		t.Fatalf("VerifyReport() error: %v", err)
	}
	if !result.Valid {
		t.Error("expected valid result")
	}
}

func TestSNPReportVerifier_UntrustedMeasurement(t *testing.T) {
	t.Parallel()
	vm, _ := NewSNPVM(nil)
	report, _ := vm.GetAttestationReport([SNPReportDataSize]byte{})

	verifier := NewSNPReportVerifier()
	// Add a different trusted measurement
	var fakeMeasurement [MeasurementSize]byte
	fakeMeasurement[0] = 0xFF
	verifier.AddTrustedMeasurement(fakeMeasurement)

	_, err := verifier.VerifyReport(report)
	if err == nil {
		t.Error("expected untrusted measurement error")
	}
}

func TestSNPReportVerifier_TrustedMeasurement(t *testing.T) {
	t.Parallel()
	vm, _ := NewSNPVM(nil)
	report, _ := vm.GetAttestationReport([SNPReportDataSize]byte{})

	verifier := NewSNPReportVerifier()
	verifier.AddTrustedMeasurement(report.Measurement)

	result, err := verifier.VerifyReport(report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Error("expected valid")
	}
}

func TestSNPReportVerifier_TCBBelowMinimum(t *testing.T) {
	t.Parallel()
	vm, _ := NewSNPVM(nil)
	report, _ := vm.GetAttestationReport([SNPReportDataSize]byte{})

	verifier := NewSNPReportVerifier()
	verifier.SetMinTCB(TCBVersion{SNP: 255}) // Very high min

	_, err := verifier.VerifyReport(report)
	if err == nil {
		t.Error("expected TCB version error")
	}
}

func TestSNPReportVerifier_PolicyViolation_Debug(t *testing.T) {
	t.Parallel()
	cfg := DefaultSNPVMConfig()
	cfg.Policy.Debug = true // VM has debug enabled
	vm, _ := NewSNPVM(cfg)
	report, _ := vm.GetAttestationReport([SNPReportDataSize]byte{})

	verifier := NewSNPReportVerifier()
	verifier.SetRequiredPolicy(&GuestPolicy{Debug: true}) // Debug not allowed

	_, err := verifier.VerifyReport(report)
	if err == nil {
		t.Error("expected policy violation error for debug mode")
	}
}

func TestSNPReportVerifier_PolicyViolation_VMPL(t *testing.T) {
	t.Parallel()
	cfg := DefaultSNPVMConfig()
	cfg.Policy.VMPLRequired = false
	vm, _ := NewSNPVM(cfg)
	report, _ := vm.GetAttestationReport([SNPReportDataSize]byte{})

	verifier := NewSNPReportVerifier()
	verifier.SetRequiredPolicy(&GuestPolicy{VMPLRequired: true})

	_, err := verifier.VerifyReport(report)
	if err == nil {
		t.Error("expected policy violation for VMPL requirement")
	}
}

func TestSNPReportVerifier_SNPNotEnabled(t *testing.T) {
	t.Parallel()
	vm, _ := NewSNPVM(nil)
	report, _ := vm.GetAttestationReport([SNPReportDataSize]byte{})
	report.PlatformInfo.SNPEnabled = false

	verifier := NewSNPReportVerifier()
	_, err := verifier.VerifyReport(report)
	if err == nil {
		t.Error("expected error for SNP not enabled")
	}
}

func TestDeriveVMPLKey(t *testing.T) {
	t.Parallel()
	rootKey := []byte("root-key-data-for-derivation-test")
	key1 := DeriveVMPLKey(rootKey, 0, "context1")
	key2 := DeriveVMPLKey(rootKey, 1, "context1")
	key3 := DeriveVMPLKey(rootKey, 0, "context2")

	if len(key1) != 32 {
		t.Errorf("expected 32 byte key, got %d", len(key1))
	}
	// Different VMPL levels should produce different keys
	match := true
	for i := range key1 {
		if key1[i] != key2[i] {
			match = false
			break
		}
	}
	if match {
		t.Error("different VMPL levels should produce different keys")
	}
	// Different contexts should produce different keys
	match = true
	for i := range key1 {
		if key1[i] != key3[i] {
			match = false
			break
		}
	}
	if match {
		t.Error("different contexts should produce different keys")
	}
}

func TestConstants(t *testing.T) {
	t.Parallel()
	if MeasurementSize != 48 {
		t.Errorf("expected MeasurementSize=48, got %d", MeasurementSize)
	}
	if SNPReportDataSize != 64 {
		t.Errorf("expected SNPReportDataSize=64, got %d", SNPReportDataSize)
	}
	if SignatureSize != 96 {
		t.Errorf("expected SignatureSize=96, got %d", SignatureSize)
	}
	if PolicySize != 8 {
		t.Errorf("expected PolicySize=8, got %d", PolicySize)
	}
	if PlatformInfoSize != 8 {
		t.Errorf("expected PlatformInfoSize=8, got %d", PlatformInfoSize)
	}
}

func TestNewSNPVM_MeasurementMismatch(t *testing.T) {
	t.Parallel()
	cfg := DefaultSNPVMConfig()
	// Set a non-zero expected measurement that won't match
	cfg.ExpectedMeasurement = [MeasurementSize]byte{0xFF, 0xFE, 0xFD}
	_, err := NewSNPVM(cfg)
	if err == nil {
		t.Error("expected measurement mismatch error")
	}
}

func TestSNPReportVerifier_TCB_MicrocodeBelow(t *testing.T) {
	t.Parallel()
	vm, _ := NewSNPVM(nil)
	report, _ := vm.GetAttestationReport([SNPReportDataSize]byte{})

	verifier := NewSNPReportVerifier()
	verifier.SetMinTCB(TCBVersion{Microcode: 255}) // Very high min microcode

	_, err := verifier.VerifyReport(report)
	if err == nil {
		t.Error("expected TCB version error for microcode")
	}
}

func TestSNPReportVerifier_TCB_TEEBelow(t *testing.T) {
	t.Parallel()
	vm, _ := NewSNPVM(nil)
	report, _ := vm.GetAttestationReport([SNPReportDataSize]byte{})

	verifier := NewSNPReportVerifier()
	verifier.SetMinTCB(TCBVersion{TEE: 255}) // Very high min TEE

	_, err := verifier.VerifyReport(report)
	if err == nil {
		t.Error("expected TCB version error for TEE")
	}
}

func TestSNPReportVerifier_TCB_BootLoaderBelow(t *testing.T) {
	t.Parallel()
	vm, _ := NewSNPVM(nil)
	report, _ := vm.GetAttestationReport([SNPReportDataSize]byte{})

	verifier := NewSNPReportVerifier()
	verifier.SetMinTCB(TCBVersion{BootLoader: 255}) // Very high min bootloader

	_, err := verifier.VerifyReport(report)
	if err == nil {
		t.Error("expected TCB version error for BootLoader")
	}
}

func TestSNPReportVerifier_SetCerts(t *testing.T) {
	t.Parallel()
	verifier := NewSNPReportVerifier()
	certs := &AttestationCerts{
		VCEK: []byte("vcek-data"),
		ASK:  []byte("ask-data"),
		ARK:  []byte("ark-data"),
	}
	verifier.SetCerts(certs)
	if verifier.certs == nil {
		t.Error("certs should be set")
	}
}

func TestSNPReportVerifier_PolicyPassesValidation(t *testing.T) {
	t.Parallel()
	vm, _ := NewSNPVM(nil) // Default policy: Debug=false, VMPLRequired=true
	report, _ := vm.GetAttestationReport([SNPReportDataSize]byte{})

	verifier := NewSNPReportVerifier()
	// Set required policy that VM satisfies: no debug, VMPL required
	verifier.SetRequiredPolicy(&GuestPolicy{Debug: false, VMPLRequired: true})

	result, err := verifier.VerifyReport(report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Error("expected valid result")
	}
}

func TestSNPVM_Execute_MultipleOperations(t *testing.T) {
	t.Parallel()
	vm, _ := NewSNPVM(nil)

	ops := []string{"hash", "verify", "inference", "custom"}
	for _, op := range ops {
		output, err := vm.Execute(op, []byte("data"))
		if err != nil {
			t.Fatalf("Execute(%q) error: %v", op, err)
		}
		if output == nil {
			t.Fatalf("Execute(%q) output is nil", op)
		}
	}

	log := vm.GetExecutionLog()
	if len(log) != 4 {
		t.Errorf("expected 4 log entries, got %d", len(log))
	}
	for _, entry := range log {
		if !entry.Success {
			t.Errorf("expected success for %q", entry.Operation)
		}
	}
}

func TestSNPVM_GetAttestationReport_VerifiesFields(t *testing.T) {
	t.Parallel()
	vm, _ := NewSNPVM(nil)
	report, _ := vm.GetAttestationReport([SNPReportDataSize]byte{})

	if report.GuestSVN != 1 {
		t.Errorf("expected GuestSVN=1, got %d", report.GuestSVN)
	}
	if report.SignatureAlgo != 1 {
		t.Errorf("expected SignatureAlgo=1, got %d", report.SignatureAlgo)
	}
	if report.CurrentTCB.SNP != 8 {
		t.Errorf("expected TCB SNP=8, got %d", report.CurrentTCB.SNP)
	}
	if report.Signature == [SignatureSize]byte{} {
		t.Error("signature should not be zero")
	}
}
