// Package sgx provides Intel SGX TEE support for Aethelred validators
// Implements secure enclave execution for AI inference verification
package sgx

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// SGX constants
const (
	// Enclave measurement size (MRENCLAVE)
	MREnclaveSize = 32

	// Enclave signer measurement size (MRSIGNER)
	MRSignerSize = 32

	// Report data size
	ReportDataSize = 64

	// Quote size (varies, this is minimum)
	MinQuoteSize = 432
)

// SecurityVersion represents the SGX security version
type SecurityVersion struct {
	ISVVersion uint16
	CPUSVn     [16]byte
	PCESVn     uint16
}

// EnclaveAttributes contains SGX enclave attributes
type EnclaveAttributes struct {
	Flags uint64
	XFrm  uint64
}

// EnclaveIdentity contains enclave identity information
type EnclaveIdentity struct {
	MREnclave   [MREnclaveSize]byte
	MRSigner    [MRSignerSize]byte
	ProductID   uint16
	SecurityVer SecurityVersion
	Attributes  EnclaveAttributes
}

// SGXReport contains an SGX hardware report
type SGXReport struct {
	CPUSVn         [16]byte
	MiscSelect     uint32
	Reserved1      [28]byte
	Attributes     EnclaveAttributes
	MREnclave      [MREnclaveSize]byte
	Reserved2      [32]byte
	MRSigner       [MRSignerSize]byte
	Reserved3      [96]byte
	ISVProdID      uint16
	ISVSvn         uint16
	Reserved4      [60]byte
	ReportData     [ReportDataSize]byte
	KeyID          [32]byte
	MAC            [16]byte
}

// SGXQuote contains an ECDSA attestation quote
type SGXQuote struct {
	Version           uint16
	SignType          uint16
	AttestationKeyType uint16
	Reserved          uint16
	QEVenderID        uint16
	UserData          [20]byte
	ISVSvn            uint16
	PCESvn            uint16
	QEVendorID        [16]byte
	QEVendorData      [20]byte
	ReportBody        SGXReport
	SignatureLength   uint32
	Signature         []byte
}

// AttestationResult contains the result of attestation verification
type AttestationResult struct {
	Valid          bool
	EnclaveID      EnclaveIdentity
	ReportData     [ReportDataSize]byte
	Timestamp      time.Time
	VerificationID string
}

// SGXEnclave represents an SGX enclave instance
type SGXEnclave struct {
	mu sync.RWMutex

	// Enclave identity
	identity EnclaveIdentity

	// Whether enclave is initialized
	initialized bool

	// Enclave handle (simulated)
	handle uint64

	// Sealed data store
	sealedData map[string][]byte

	// Execution log
	execLog []ExecutionEntry
}

// ExecutionEntry logs an enclave execution
type ExecutionEntry struct {
	Timestamp   time.Time
	Operation   string
	InputHash   [32]byte
	OutputHash  [32]byte
	GasUsed     uint64
	Success     bool
}

// EnclaveConfig configures an SGX enclave
type EnclaveConfig struct {
	// Path to signed enclave binary
	EnclavePath string

	// Enclave debug mode (development only)
	Debug bool

	// Heap size in bytes
	HeapSize uint64

	// Stack size in bytes
	StackSize uint64

	// Number of TCS (Thread Control Structures)
	NumTCS int

	// Expected MRENCLAVE for verification
	ExpectedMREnclave [MREnclaveSize]byte

	// Expected MRSIGNER for verification
	ExpectedMRSigner [MRSignerSize]byte
}

// DefaultEnclaveConfig returns default configuration
func DefaultEnclaveConfig() *EnclaveConfig {
	return &EnclaveConfig{
		Debug:     false,
		HeapSize:  256 * 1024 * 1024, // 256 MB
		StackSize: 2 * 1024 * 1024,   // 2 MB
		NumTCS:    4,
	}
}

// NewSGXEnclave creates a new SGX enclave
func NewSGXEnclave(config *EnclaveConfig) (*SGXEnclave, error) {
	if config == nil {
		config = DefaultEnclaveConfig()
	}

	enclave := &SGXEnclave{
		sealedData: make(map[string][]byte),
		execLog:    make([]ExecutionEntry, 0),
	}

	// Initialize enclave (simulated)
	if err := enclave.initialize(config); err != nil {
		return nil, err
	}

	return enclave, nil
}

// initialize initializes the enclave
func (e *SGXEnclave) initialize(config *EnclaveConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// In production, this would:
	// 1. Load the signed enclave binary
	// 2. Create the enclave using ECREATE
	// 3. Add pages using EADD
	// 4. Initialize using EINIT
	// 5. Verify MRENCLAVE matches expected value

	// Simulate enclave initialization
	e.handle = uint64(time.Now().UnixNano())

	// Generate simulated identity
	h := sha256.Sum256([]byte(fmt.Sprintf("aethelred-sgx-enclave-%d", e.handle)))
	copy(e.identity.MREnclave[:], h[:])

	h = sha256.Sum256([]byte("aethelred-signer"))
	copy(e.identity.MRSigner[:], h[:])

	e.identity.ProductID = 1
	e.identity.SecurityVer.ISVVersion = 1
	e.identity.Attributes.Flags = 0x04 // MODE64BIT

	// Verify against expected measurements if provided
	if config.ExpectedMREnclave != [MREnclaveSize]byte{} {
		if e.identity.MREnclave != config.ExpectedMREnclave {
			return errors.New("MRENCLAVE mismatch")
		}
	}

	e.initialized = true
	return nil
}

// Execute runs code in the enclave
func (e *SGXEnclave) Execute(operation string, input []byte) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.initialized {
		return nil, errors.New("enclave not initialized")
	}

	entry := ExecutionEntry{
		Timestamp: time.Now(),
		Operation: operation,
		InputHash: sha256.Sum256(input),
	}

	// In production, this would:
	// 1. Enter the enclave using EENTER
	// 2. Execute the requested operation
	// 3. Exit the enclave using EEXIT
	// 4. Return the result

	// Simulate execution
	output := e.simulateExecution(operation, input)
	entry.OutputHash = sha256.Sum256(output)
	entry.Success = true

	e.execLog = append(e.execLog, entry)

	return output, nil
}

// simulateExecution simulates enclave execution
func (e *SGXEnclave) simulateExecution(operation string, input []byte) []byte {
	// Simulate different operations
	switch operation {
	case "hash":
		h := sha256.Sum256(input)
		return h[:]
	case "verify":
		// Simulate verification
		return []byte{1} // Success
	case "inference":
		// Simulate ML inference
		return []byte{0, 0, 0, 0} // Placeholder result
	default:
		return input
	}
}

// GetQuote generates an attestation quote
func (e *SGXEnclave) GetQuote(reportData [ReportDataSize]byte) (*SGXQuote, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.initialized {
		return nil, errors.New("enclave not initialized")
	}

	// In production, this would:
	// 1. Generate a REPORT targeting the QE (Quoting Enclave)
	// 2. Send REPORT to QE
	// 3. QE generates QUOTE with ECDSA signature

	// Simulate quote generation
	quote := &SGXQuote{
		Version:           3,
		SignType:          2, // ECDSA_P256
		AttestationKeyType: 2,
	}

	quote.ReportBody.MREnclave = e.identity.MREnclave
	quote.ReportBody.MRSigner = e.identity.MRSigner
	quote.ReportBody.ISVProdID = e.identity.ProductID
	quote.ReportBody.ISVSvn = e.identity.SecurityVer.ISVVersion
	quote.ReportBody.ReportData = reportData
	quote.ReportBody.Attributes = e.identity.Attributes

	// Generate simulated signature
	sigData := make([]byte, 0)
	sigData = append(sigData, quote.ReportBody.MREnclave[:]...)
	sigData = append(sigData, reportData[:]...)
	sigHash := sha256.Sum256(sigData)

	quote.SignatureLength = 64
	quote.Signature = sigHash[:] // Simulated signature

	return quote, nil
}

// SealData seals data using the enclave's sealing key
func (e *SGXEnclave) SealData(label string, data []byte) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.initialized {
		return nil, errors.New("enclave not initialized")
	}

	// In production, this would:
	// 1. Derive sealing key using EGETKEY
	// 2. Encrypt data with sealing key
	// 3. Add MAC for integrity

	// Simulate sealing
	sealed := make([]byte, len(data)+48) // Data + header + MAC
	copy(sealed[:32], e.identity.MREnclave[:])
	binary.LittleEndian.PutUint32(sealed[32:36], uint32(len(data)))
	copy(sealed[48:], data)

	// Add simulated MAC
	mac := sha256.Sum256(sealed[:48+len(data)])
	copy(sealed[36:48], mac[:12])

	e.sealedData[label] = sealed
	return sealed, nil
}

// UnsealData unseals previously sealed data
func (e *SGXEnclave) UnsealData(label string, sealed []byte) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.initialized {
		return nil, errors.New("enclave not initialized")
	}

	if len(sealed) < 48 {
		return nil, errors.New("sealed data too short")
	}

	// Verify MRENCLAVE matches
	var sealedMREnclave [MREnclaveSize]byte
	copy(sealedMREnclave[:], sealed[:32])
	if sealedMREnclave != e.identity.MREnclave {
		return nil, errors.New("MRENCLAVE mismatch - cannot unseal")
	}

	// Extract data length
	dataLen := binary.LittleEndian.Uint32(sealed[32:36])
	if int(dataLen)+48 > len(sealed) {
		return nil, errors.New("invalid sealed data length")
	}

	// Verify MAC
	mac := sha256.Sum256(sealed[:48+dataLen])
	if string(sealed[36:48]) != string(mac[:12]) {
		return nil, errors.New("MAC verification failed")
	}

	data := make([]byte, dataLen)
	copy(data, sealed[48:48+dataLen])
	return data, nil
}

// GetIdentity returns the enclave identity
func (e *SGXEnclave) GetIdentity() EnclaveIdentity {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.identity
}

// GetMREnclave returns the MRENCLAVE measurement
func (e *SGXEnclave) GetMREnclave() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return hex.EncodeToString(e.identity.MREnclave[:])
}

// GetMRSigner returns the MRSIGNER measurement
func (e *SGXEnclave) GetMRSigner() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return hex.EncodeToString(e.identity.MRSigner[:])
}

// GetExecutionLog returns the execution log
func (e *SGXEnclave) GetExecutionLog() []ExecutionEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()
	log := make([]ExecutionEntry, len(e.execLog))
	copy(log, e.execLog)
	return log
}

// Destroy destroys the enclave
func (e *SGXEnclave) Destroy() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// In production, this would call EDESTROY
	e.initialized = false
	e.handle = 0
	e.sealedData = nil
	e.execLog = nil

	return nil
}

// SGXQuoteVerifier verifies SGX attestation quotes
type SGXQuoteVerifier struct {
	// Trusted MRENCLAVE values
	trustedEnclaves map[[MREnclaveSize]byte]bool

	// Trusted MRSIGNER values
	trustedSigners map[[MRSignerSize]byte]bool

	// Minimum security version
	minSecurityVersion uint16
}

// NewSGXQuoteVerifier creates a new quote verifier
func NewSGXQuoteVerifier() *SGXQuoteVerifier {
	return &SGXQuoteVerifier{
		trustedEnclaves: make(map[[MREnclaveSize]byte]bool),
		trustedSigners:  make(map[[MRSignerSize]byte]bool),
		minSecurityVersion: 0,
	}
}

// AddTrustedEnclave adds a trusted MRENCLAVE
func (v *SGXQuoteVerifier) AddTrustedEnclave(mrEnclave [MREnclaveSize]byte) {
	v.trustedEnclaves[mrEnclave] = true
}

// AddTrustedSigner adds a trusted MRSIGNER
func (v *SGXQuoteVerifier) AddTrustedSigner(mrSigner [MRSignerSize]byte) {
	v.trustedSigners[mrSigner] = true
}

// SetMinSecurityVersion sets minimum required security version
func (v *SGXQuoteVerifier) SetMinSecurityVersion(version uint16) {
	v.minSecurityVersion = version
}

// VerifyQuote verifies an SGX quote
func (v *SGXQuoteVerifier) VerifyQuote(quote *SGXQuote) (*AttestationResult, error) {
	result := &AttestationResult{
		Timestamp:      time.Now(),
		VerificationID: hex.EncodeToString(quote.ReportBody.MREnclave[:8]),
	}

	// Check MRENCLAVE
	if len(v.trustedEnclaves) > 0 {
		if !v.trustedEnclaves[quote.ReportBody.MREnclave] {
			return result, errors.New("untrusted MRENCLAVE")
		}
	}

	// Check MRSIGNER
	if len(v.trustedSigners) > 0 {
		if !v.trustedSigners[quote.ReportBody.MRSigner] {
			return result, errors.New("untrusted MRSIGNER")
		}
	}

	// Check security version
	if quote.ReportBody.ISVSvn < v.minSecurityVersion {
		return result, fmt.Errorf("security version %d below minimum %d",
			quote.ReportBody.ISVSvn, v.minSecurityVersion)
	}

	// In production, would also:
	// 1. Verify ECDSA signature using Intel's public key
	// 2. Check quote freshness
	// 3. Verify TCB status with Intel's attestation service

	result.Valid = true
	result.EnclaveID = EnclaveIdentity{
		MREnclave: quote.ReportBody.MREnclave,
		MRSigner:  quote.ReportBody.MRSigner,
		ProductID: quote.ReportBody.ISVProdID,
		SecurityVer: SecurityVersion{
			ISVVersion: quote.ReportBody.ISVSvn,
		},
		Attributes: quote.ReportBody.Attributes,
	}
	result.ReportData = quote.ReportBody.ReportData

	return result, nil
}
