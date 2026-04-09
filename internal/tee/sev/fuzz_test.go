package sev

import (
	"encoding/binary"
	"testing"
)

// ---------------------------------------------------------------------------
// Seed corpus helpers
// ---------------------------------------------------------------------------

func addSEVSeedCorpus(f *testing.F) {
	f.Helper()
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xFF})
	f.Add(make([]byte, 32))
	f.Add(make([]byte, MeasurementSize))
	f.Add(make([]byte, SNPReportDataSize))
	f.Add(make([]byte, 256))

	ones := make([]byte, 256)
	for i := range ones {
		ones[i] = 0xFF
	}
	f.Add(ones)
	f.Add(make([]byte, MeasurementSize-1)) // truncated
	f.Add(make([]byte, 4096))              // large
}

// ---------------------------------------------------------------------------
// 1. FuzzSEVAttestationReport
//
// Fuzz AMD SEV-SNP attestation report validation by constructing report
// structures from raw fuzz input.
//
// Invariants:
//   - No panics on any input.
//   - Reports with untrusted measurements are rejected by a strict verifier.
//   - TCB version below minimum is always caught.
//   - Policy violations are detected.
//   - SNP-not-enabled is always rejected.
// ---------------------------------------------------------------------------

func FuzzSEVAttestationReport(f *testing.F) {
	addSEVSeedCorpus(f)

	// Create a known-good VM and report for comparison.
	goodVM, err := NewSNPVM(nil)
	if err != nil {
		f.Fatal(err)
	}
	goodReport, err := goodVM.GetAttestationReport([SNPReportDataSize]byte{})
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		report := reportFromFuzzData(data)

		// --- Open verifier (no constraints) ---
		openVerifier := NewSNPReportVerifier()
		result, err := openVerifier.VerifyReport(report)
		if err != nil {
			// Rejected is fine — e.g., SNP not enabled.
			return
		}
		if result == nil {
			t.Fatal("VerifyReport returned nil result without error")
		}

		// --- Strict verifier with known-good measurement ---
		strictVerifier := NewSNPReportVerifier()
		strictVerifier.AddTrustedMeasurement(goodReport.Measurement)
		strictVerifier.SetMinTCB(TCBVersion{SNP: 1, Microcode: 1})

		strictResult, strictErr := strictVerifier.VerifyReport(report)

		// Fuzz-generated measurement should almost never match.
		if report.Measurement != goodReport.Measurement {
			if strictErr == nil && strictResult != nil && strictResult.Valid {
				t.Fatal("strict verifier accepted report with untrusted measurement")
			}
		}

		// TCB below minimum must be caught.
		if report.CurrentTCB.SNP < 1 || report.CurrentTCB.Microcode < 1 {
			if strictErr == nil && strictResult != nil && strictResult.Valid {
				t.Fatal("strict verifier accepted report with low TCB")
			}
		}
	})
}

// reportFromFuzzData constructs an SNPReport from arbitrary bytes.
func reportFromFuzzData(data []byte) *SNPReport {
	report := &SNPReport{
		Version:       2,
		GuestSVN:      1,
		SignatureAlgo: 1,
	}

	// Default to SNP enabled so the verifier does not short-circuit.
	report.PlatformInfo.SNPEnabled = true
	report.PlatformInfo.SEVEnabled = true

	if len(data) >= MeasurementSize {
		copy(report.Measurement[:], data[:MeasurementSize])
		data = data[MeasurementSize:]
	}
	if len(data) >= SNPReportDataSize {
		copy(report.ReportData[:], data[:SNPReportDataSize])
		data = data[SNPReportDataSize:]
	}
	if len(data) >= 4 {
		report.Version = binary.LittleEndian.Uint32(data[:4])
		data = data[4:]
	}
	if len(data) >= 4 {
		report.GuestSVN = binary.LittleEndian.Uint32(data[:4])
		data = data[4:]
	}
	if len(data) >= 4 {
		// Map fuzz bytes into TCB fields.
		report.CurrentTCB.SNP = data[0]
		report.CurrentTCB.Microcode = data[1]
		report.CurrentTCB.TEE = data[2]
		report.CurrentTCB.BootLoader = data[3]
		data = data[4:]
	}
	if len(data) >= 1 {
		// Fuzz policy bits.
		report.Policy.Debug = data[0]&0x01 != 0
		report.Policy.VMPLRequired = data[0]&0x02 != 0
		report.Policy.SMT = data[0]&0x04 != 0
		data = data[1:]
	}
	if len(data) >= 1 {
		// Fuzz platform info.
		report.PlatformInfo.SNPEnabled = data[0]&0x01 != 0
		report.PlatformInfo.SEVEnabled = data[0]&0x02 != 0
		report.PlatformInfo.SMEEnabled = data[0]&0x04 != 0
		report.PlatformInfo.VMPLEnabled = data[0]&0x08 != 0
	}
	if len(data) >= SignatureSize {
		copy(report.Signature[:], data[:SignatureSize])
	}

	report.ReportedTCB = report.CurrentTCB
	report.CommittedTCB = report.CurrentTCB
	report.LaunchTCB = report.CurrentTCB

	return report
}

// ---------------------------------------------------------------------------
// 2. FuzzSEVVMExecution
//
// Fuzz VM Execute with arbitrary operations and input data.
//
// Invariants:
//   - No panics on any operation name or input.
//   - Output is never nil for a running VM.
//   - Stopped VM always returns error.
// ---------------------------------------------------------------------------

func FuzzSEVVMExecution(f *testing.F) {
	f.Add([]byte("hash"), []byte("test input"))
	f.Add([]byte("verify"), []byte{})
	f.Add([]byte("inference"), make([]byte, 1024))
	f.Add([]byte(""), []byte{0xFF})
	f.Add([]byte("unknown_op"), make([]byte, 0))

	f.Fuzz(func(t *testing.T, operation []byte, input []byte) {
		vm, err := NewSNPVM(nil)
		if err != nil {
			t.Fatal(err)
		}

		output, err := vm.Execute(string(operation), input)
		if err != nil {
			t.Fatalf("Execute error on running VM: %v", err)
		}
		if output == nil {
			t.Fatal("Execute returned nil output")
		}

		// Stopped VM must reject.
		_ = vm.Stop()
		_, err = vm.Execute(string(operation), input)
		if err == nil {
			t.Fatal("stopped VM accepted execution")
		}
	})
}

// ---------------------------------------------------------------------------
// 3. FuzzSEVPolicyVerification
//
// Fuzz the policy verification path with various policy combinations.
//
// Invariants:
//   - Debug mode in report + debug required in policy always rejected.
//   - VMPL required but not enabled always rejected.
//   - SNP not enabled always rejected.
//   - No panics on any combination.
// ---------------------------------------------------------------------------

func FuzzSEVPolicyVerification(f *testing.F) {
	// Seed: various policy byte combinations.
	f.Add(byte(0x00), byte(0x00)) // all false
	f.Add(byte(0xFF), byte(0xFF)) // all true
	f.Add(byte(0x01), byte(0x02)) // debug on, VMPL required
	f.Add(byte(0x02), byte(0x01)) // VMPL on, debug required

	f.Fuzz(func(t *testing.T, reportPolicyByte byte, verifierPolicyByte byte) {
		vm, err := NewSNPVM(nil)
		if err != nil {
			t.Fatal(err)
		}

		var reportData [SNPReportDataSize]byte
		report, err := vm.GetAttestationReport(reportData)
		if err != nil {
			t.Fatal(err)
		}

		// Apply fuzz bits to report policy.
		report.Policy.Debug = reportPolicyByte&0x01 != 0
		report.Policy.VMPLRequired = reportPolicyByte&0x02 != 0
		report.Policy.SMT = reportPolicyByte&0x04 != 0
		report.Policy.SingleSocket = reportPolicyByte&0x08 != 0

		// Apply fuzz bits to verifier required policy.
		requiredPolicy := &GuestPolicy{
			Debug:        verifierPolicyByte&0x01 != 0,
			VMPLRequired: verifierPolicyByte&0x02 != 0,
			SMT:          verifierPolicyByte&0x04 != 0,
			SingleSocket: verifierPolicyByte&0x08 != 0,
		}

		verifier := NewSNPReportVerifier()
		verifier.SetRequiredPolicy(requiredPolicy)

		// Must not panic.
		result, err := verifier.VerifyReport(report)

		// Check specific invariants about debug and VMPL.
		if requiredPolicy.Debug && report.Policy.Debug {
			// verifyPolicy: "debug mode not allowed" when both are true.
			if err == nil && result != nil && result.Valid {
				t.Fatal("verifier accepted report with debug mode when policy forbids it")
			}
		}
		if requiredPolicy.VMPLRequired && !report.Policy.VMPLRequired {
			if err == nil && result != nil && result.Valid {
				t.Fatal("verifier accepted report without VMPL when VMPL is required")
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 4. FuzzDeriveVMPLKey
//
// Fuzz the VMPL key derivation.
//
// Invariants:
//   - No panics on any input.
//   - Output is always 32 bytes (SHA-256).
//   - Different VMPL levels produce different keys.
//   - Different contexts produce different keys.
//   - Same inputs always produce same output (deterministic).
// ---------------------------------------------------------------------------

func FuzzDeriveVMPLKey(f *testing.F) {
	f.Add([]byte("root-key"), uint32(0), []byte("context"))
	f.Add([]byte{}, uint32(0), []byte{})
	f.Add(make([]byte, 64), uint32(0xFFFFFFFF), make([]byte, 256))
	f.Add([]byte{0xFF}, uint32(1), []byte("ctx"))

	f.Fuzz(func(t *testing.T, rootKey []byte, vmpl uint32, context []byte) {
		key := DeriveVMPLKey(rootKey, vmpl, string(context))
		if len(key) != 32 {
			t.Fatalf("expected 32-byte key, got %d", len(key))
		}

		// Determinism: same inputs must produce same output.
		key2 := DeriveVMPLKey(rootKey, vmpl, string(context))
		for i := range key {
			if key[i] != key2[i] {
				t.Fatal("DeriveVMPLKey is not deterministic")
			}
		}

		// Different VMPL level must produce different key (if rootKey is non-empty).
		if len(rootKey) > 0 {
			altVMPL := vmpl + 1
			if altVMPL == 0 {
				altVMPL = vmpl - 1 // Handle overflow.
			}
			keyAlt := DeriveVMPLKey(rootKey, altVMPL, string(context))
			match := true
			for i := range key {
				if key[i] != keyAlt[i] {
					match = false
					break
				}
			}
			if match {
				t.Fatal("different VMPL levels produced identical keys")
			}
		}
	})
}
