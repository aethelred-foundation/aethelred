// Package sev provides AMD SEV-SNP TEE support for Aethelred validators
// Implements Secure Encrypted Virtualization with Secure Nested Paging
package sev

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// SNP constants
const (
	// Measurement size
	MeasurementSize = 48

	// Report data size
	SNPReportDataSize = 64

	// Guest policy size
	PolicySize = 8

	// Platform info size
	PlatformInfoSize = 8

	// Signature size (ECDSA P-384)
	SignatureSize = 96
)

// TCBVersion represents the Trusted Computing Base version
type TCBVersion struct {
	BootLoader   uint8
	TEE          uint8
	Reserved     [4]uint8
	SNP          uint8
	Microcode    uint8
}

// GuestPolicy defines VM security policy
type GuestPolicy struct {
	ABIMinor         uint8
	ABIMajor         uint8
	SMT              bool    // Simultaneous Multi-Threading allowed
	MigrateMA        bool    // Migration agent allowed
	Debug            bool    // Debug mode allowed
	SingleSocket     bool    // Single socket only
	CXLAllowed       bool    // CXL devices allowed
	MemAESAllowed    bool    // Memory AES-256-XTS allowed
	RASPAllowed      bool    // Reverse MAP allowed
	VMPLRequired     bool    // VMPL required
	Flags            uint8
}

// PlatformInfo contains platform configuration
type PlatformInfo struct {
	SMEEnabled       bool
	SEVEnabled       bool
	SNPEnabled       bool
	VMPLEnabled      bool
	TSME             bool
	PlatformVersion  uint8
}

// SNPReport contains an AMD SEV-SNP attestation report
type SNPReport struct {
	Version           uint32
	GuestSVN          uint32
	Policy            GuestPolicy
	FamilyID          [16]byte
	ImageID           [16]byte
	VMPL              uint32
	SignatureAlgo     uint32
	CurrentTCB        TCBVersion
	PlatformInfo      PlatformInfo
	AuthorKeyEn       uint32
	Reserved1         uint32
	ReportData        [SNPReportDataSize]byte
	Measurement       [MeasurementSize]byte
	HostData          [32]byte
	IDKeyDigest       [48]byte
	AuthorKeyDigest   [48]byte
	ReportID          [32]byte
	ReportIDMA        [32]byte
	ReportedTCB       TCBVersion
	Reserved2         [24]byte
	ChipID            [64]byte
	CommittedTCB      TCBVersion
	CurrentBuild      uint8
	CurrentMinor      uint8
	CurrentMajor      uint8
	Reserved3         uint8
	CommittedBuild    uint8
	CommittedMinor    uint8
	CommittedMajor    uint8
	Reserved4         uint8
	LaunchTCB         TCBVersion
	Reserved5         [168]byte
	Signature         [SignatureSize]byte
}

// AttestationCerts contains the certificate chain for verification
type AttestationCerts struct {
	VCEK []byte // Versioned Chip Endorsement Key
	ASK  []byte // AMD SEV Signing Key
	ARK  []byte // AMD Root Key
}

// SNPAttestationResult contains the result of SNP attestation verification
type SNPAttestationResult struct {
	Valid            bool
	Measurement      [MeasurementSize]byte
	ReportData       [SNPReportDataSize]byte
	Policy           GuestPolicy
	TCBVersion       TCBVersion
	PlatformInfo     PlatformInfo
	Timestamp        time.Time
	VerificationID   string
}

// SNPVM represents an AMD SEV-SNP protected VM
type SNPVM struct {
	mu sync.RWMutex

	// VM identifier
	vmID string

	// Guest measurement
	measurement [MeasurementSize]byte

	// Guest policy
	policy GuestPolicy

	// Launch digest
	launchDigest [48]byte

	// Whether VM is running
	running bool

	// Execution log
	execLog []SNPExecutionEntry
}

// SNPExecutionEntry logs a VM execution
type SNPExecutionEntry struct {
	Timestamp   time.Time
	Operation   string
	InputHash   [32]byte
	OutputHash  [32]byte
	Success     bool
}

// SNPVMConfig configures an SNP-protected VM
type SNPVMConfig struct {
	// VM identifier
	VMID string

	// Guest kernel/firmware image
	ImagePath string

	// Memory size in MB
	MemoryMB uint64

	// Number of vCPUs
	NumCPUs int

	// Guest policy settings
	Policy GuestPolicy

	// Expected measurement for verification
	ExpectedMeasurement [MeasurementSize]byte

	// Host data to include in attestation
	HostData [32]byte
}

// DefaultSNPVMConfig returns default VM configuration
func DefaultSNPVMConfig() *SNPVMConfig {
	return &SNPVMConfig{
		MemoryMB: 4096,
		NumCPUs:  4,
		Policy: GuestPolicy{
			ABIMajor:     1,
			ABIMinor:     0,
			SMT:          true,
			Debug:        false,
			SingleSocket: false,
			VMPLRequired: true,
		},
	}
}

// NewSNPVM creates a new SNP-protected VM
func NewSNPVM(config *SNPVMConfig) (*SNPVM, error) {
	if config == nil {
		config = DefaultSNPVMConfig()
	}

	vm := &SNPVM{
		vmID:    config.VMID,
		policy:  config.Policy,
		execLog: make([]SNPExecutionEntry, 0),
	}

	// Initialize VM (simulated)
	if err := vm.initialize(config); err != nil {
		return nil, err
	}

	return vm, nil
}

// initialize sets up the SNP VM
func (vm *SNPVM) initialize(config *SNPVMConfig) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// In production, this would:
	// 1. Create VM with SNP enabled (SNP_LAUNCH_START)
	// 2. Add encrypted memory pages (SNP_LAUNCH_UPDATE)
	// 3. Compute launch measurement
	// 4. Finalize launch (SNP_LAUNCH_FINISH)
	// 5. Start VM execution

	// Simulate measurement calculation
	h := sha512.New384()
	h.Write([]byte(config.VMID))
	h.Write([]byte(config.ImagePath))
	h.Write(config.HostData[:])
	copy(vm.measurement[:], h.Sum(nil))

	// Verify measurement if expected value provided
	if config.ExpectedMeasurement != [MeasurementSize]byte{} {
		if vm.measurement != config.ExpectedMeasurement {
			return errors.New("measurement mismatch")
		}
	}

	// Calculate launch digest
	h.Reset()
	h.Write(vm.measurement[:])
	binary.Write(h, binary.LittleEndian, config.Policy.ABIMajor)
	binary.Write(h, binary.LittleEndian, config.Policy.ABIMinor)
	copy(vm.launchDigest[:], h.Sum(nil))

	vm.running = true
	return nil
}

// Execute runs an operation in the protected VM
func (vm *SNPVM) Execute(operation string, input []byte) ([]byte, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running {
		return nil, errors.New("VM not running")
	}

	entry := SNPExecutionEntry{
		Timestamp: time.Now(),
		Operation: operation,
		InputHash: sha256.Sum256(input),
	}

	// In production, this would:
	// 1. Send operation to guest VM via virtio or shared memory
	// 2. Guest processes in encrypted memory
	// 3. Result returned through secure channel
	// 4. Verify integrity of result

	// Simulate execution
	output := vm.simulateExecution(operation, input)
	entry.OutputHash = sha256.Sum256(output)
	entry.Success = true

	vm.execLog = append(vm.execLog, entry)

	return output, nil
}

// simulateExecution simulates VM execution
func (vm *SNPVM) simulateExecution(operation string, input []byte) []byte {
	switch operation {
	case "hash":
		h := sha256.Sum256(input)
		return h[:]
	case "verify":
		return []byte{1}
	case "inference":
		return []byte{0, 0, 0, 0}
	default:
		return input
	}
}

// GetAttestationReport generates an SNP attestation report
func (vm *SNPVM) GetAttestationReport(reportData [SNPReportDataSize]byte) (*SNPReport, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	if !vm.running {
		return nil, errors.New("VM not running")
	}

	// In production, this would:
	// 1. Guest requests report via SNP_GUEST_REQUEST
	// 2. PSP generates and signs report
	// 3. Report returned to guest
	// 4. Guest provides to verifier

	report := &SNPReport{
		Version:       2,
		GuestSVN:      1,
		Policy:        vm.policy,
		VMPL:          0,
		SignatureAlgo: 1, // ECDSA P-384
	}

	copy(report.Measurement[:], vm.measurement[:])
	report.ReportData = reportData

	// Set TCB versions (simulated)
	report.CurrentTCB = TCBVersion{
		BootLoader: 3,
		TEE:        0,
		SNP:        8,
		Microcode:  115,
	}
	report.ReportedTCB = report.CurrentTCB
	report.CommittedTCB = report.CurrentTCB
	report.LaunchTCB = report.CurrentTCB

	// Set platform info
	report.PlatformInfo = PlatformInfo{
		SMEEnabled:  true,
		SEVEnabled:  true,
		SNPEnabled:  true,
		VMPLEnabled: true,
	}

	// Generate simulated signature
	h := sha512.New384()
	h.Write(report.Measurement[:])
	h.Write(reportData[:])
	sigHash := h.Sum(nil)
	copy(report.Signature[:], sigHash)

	return report, nil
}

// GetMeasurement returns the VM measurement
func (vm *SNPVM) GetMeasurement() string {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return hex.EncodeToString(vm.measurement[:])
}

// GetExecutionLog returns the execution log
func (vm *SNPVM) GetExecutionLog() []SNPExecutionEntry {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	log := make([]SNPExecutionEntry, len(vm.execLog))
	copy(log, vm.execLog)
	return log
}

// Stop stops the VM
func (vm *SNPVM) Stop() error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	vm.running = false
	return nil
}

// Destroy destroys the VM
func (vm *SNPVM) Destroy() error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	vm.running = false
	vm.execLog = nil
	return nil
}

// SNPReportVerifier verifies SNP attestation reports
type SNPReportVerifier struct {
	// Trusted measurements
	trustedMeasurements map[[MeasurementSize]byte]bool

	// Minimum TCB version
	minTCB TCBVersion

	// Required policy settings
	requiredPolicy *GuestPolicy

	// Certificate chain for signature verification
	certs *AttestationCerts
}

// NewSNPReportVerifier creates a new report verifier
func NewSNPReportVerifier() *SNPReportVerifier {
	return &SNPReportVerifier{
		trustedMeasurements: make(map[[MeasurementSize]byte]bool),
	}
}

// AddTrustedMeasurement adds a trusted measurement
func (v *SNPReportVerifier) AddTrustedMeasurement(measurement [MeasurementSize]byte) {
	v.trustedMeasurements[measurement] = true
}

// SetMinTCB sets minimum required TCB version
func (v *SNPReportVerifier) SetMinTCB(tcb TCBVersion) {
	v.minTCB = tcb
}

// SetRequiredPolicy sets required policy constraints
func (v *SNPReportVerifier) SetRequiredPolicy(policy *GuestPolicy) {
	v.requiredPolicy = policy
}

// SetCerts sets the certificate chain for verification
func (v *SNPReportVerifier) SetCerts(certs *AttestationCerts) {
	v.certs = certs
}

// VerifyReport verifies an SNP attestation report
func (v *SNPReportVerifier) VerifyReport(report *SNPReport) (*SNPAttestationResult, error) {
	result := &SNPAttestationResult{
		Measurement:    report.Measurement,
		ReportData:     report.ReportData,
		Policy:         report.Policy,
		TCBVersion:     report.CurrentTCB,
		PlatformInfo:   report.PlatformInfo,
		Timestamp:      time.Now(),
		VerificationID: hex.EncodeToString(report.Measurement[:8]),
	}

	// Verify measurement
	if len(v.trustedMeasurements) > 0 {
		if !v.trustedMeasurements[report.Measurement] {
			return result, errors.New("untrusted measurement")
		}
	}

	// Verify TCB version
	if !v.tcbAtLeast(report.CurrentTCB, v.minTCB) {
		return result, errors.New("TCB version below minimum")
	}

	// Verify policy
	if v.requiredPolicy != nil {
		if err := v.verifyPolicy(report.Policy); err != nil {
			return result, err
		}
	}

	// Verify SNP is enabled
	if !report.PlatformInfo.SNPEnabled {
		return result, errors.New("SNP not enabled")
	}

	// In production, would also:
	// 1. Verify ECDSA P-384 signature using VCEK
	// 2. Verify certificate chain (VCEK -> ASK -> ARK)
	// 3. Check revocation status
	// 4. Verify freshness

	result.Valid = true
	return result, nil
}

// tcbAtLeast checks if a >= b for TCB versions
func (v *SNPReportVerifier) tcbAtLeast(a, b TCBVersion) bool {
	if a.SNP < b.SNP {
		return false
	}
	if a.Microcode < b.Microcode {
		return false
	}
	if a.TEE < b.TEE {
		return false
	}
	if a.BootLoader < b.BootLoader {
		return false
	}
	return true
}

// verifyPolicy checks if policy meets requirements
func (v *SNPReportVerifier) verifyPolicy(policy GuestPolicy) error {
	if v.requiredPolicy.Debug && policy.Debug {
		return errors.New("debug mode not allowed")
	}
	if v.requiredPolicy.VMPLRequired && !policy.VMPLRequired {
		return errors.New("VMPL required but not enabled")
	}
	return nil
}

// DeriveVMPLKey derives a key for a specific VMPL level
func DeriveVMPLKey(rootKey []byte, vmpl uint32, context string) []byte {
	h := sha256.New()
	h.Write(rootKey)
	binary.Write(h, binary.LittleEndian, vmpl)
	h.Write([]byte(context))
	return h.Sum(nil)
}
