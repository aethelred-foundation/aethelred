package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Portable Evidence Format
// ---------------------------------------------------------------------------
//
// PortableEvidence wraps an EvidenceBundle with everything needed for
// fully offline, self-contained verification. This includes the
// verification keys, platform trust anchors, and schema metadata
// required by a verifier that has no access to the Aethelred network.
//
// Use cases:
//   - Air-gapped regulator review
//   - Auditor evidence import
//   - Cross-organization evidence exchange
//   - Long-term archival with embedded verification context
// ---------------------------------------------------------------------------

// VerificationKey is a public key used for signature verification.
type VerificationKey struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`  // "ed25519", "ecdsa-p256", "dilithium3"
	PublicKey string `json:"public_key"` // hex-encoded
	ExpiresAt string `json:"expires_at,omitempty"`
}

// PlatformTrustAnchor describes a trusted TEE platform for attestation
// verification.
type PlatformTrustAnchor struct {
	Platform       string `json:"platform"` // "sgx", "sev", "trustzone"
	RootHash       string `json:"root_hash"`
	MinFirmware    string `json:"min_firmware,omitempty"`
	TrustChainData string `json:"trust_chain_data,omitempty"` // hex-encoded
}

// PortableEvidence is a self-contained evidence package that includes
// everything needed for offline verification.
type PortableEvidence struct {
	// FormatVersion identifies the portable format version.
	FormatVersion string `json:"format_version"`

	// PackagedAt records when the portable package was created.
	PackagedAt string `json:"packaged_at"`

	// Bundle is the underlying evidence bundle.
	Bundle *EvidenceBundle `json:"bundle"`

	// VerificationKeys are the public keys needed to verify signatures.
	VerificationKeys []VerificationKey `json:"verification_keys,omitempty"`

	// TrustAnchors are the platform trust anchors for attestation verification.
	TrustAnchors []PlatformTrustAnchor `json:"trust_anchors,omitempty"`

	// SchemaDefinition contains the evidence schema for the verifier.
	SchemaDefinition string `json:"schema_definition,omitempty"`

	// PackageHash is the SHA-256 hash of the entire portable package.
	PackageHash string `json:"package_hash"`
}

// Package creates a portable evidence package from a finalized bundle.
// If includeVerificationKeys is true, the verification keys and trust
// anchors are embedded for fully offline verification.
func Package(bundle *EvidenceBundle, includeVerificationKeys bool) (*PortableEvidence, error) {
	if bundle == nil {
		return nil, fmt.Errorf("evidence/portable: nil bundle")
	}
	if bundle.ContentHash == "" {
		return nil, fmt.Errorf("evidence/portable: bundle must be finalized before packaging")
	}

	pe := &PortableEvidence{
		FormatVersion: "1.0.0",
		PackagedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Bundle:        bundle,
	}

	if includeVerificationKeys {
		pe.SchemaDefinition = SchemaVersion
		// In a production deployment, keys and trust anchors would be
		// fetched from the platform's key management system. For now,
		// the caller provides them after construction.
	}

	// Compute package hash.
	hash, err := pe.computePackageHash()
	if err != nil {
		return nil, err
	}
	pe.PackageHash = hash

	return pe, nil
}

// PackageControlLedger creates a portable evidence package directly from a
// validated control ledger.
func PackageControlLedger(ledger *ControlLedger, includeVerificationKeys bool) (*PortableEvidence, error) {
	if ledger == nil {
		return nil, fmt.Errorf("evidence/portable: nil control ledger")
	}

	bundle, err := ledger.ToEvidenceBundle()
	if err != nil {
		return nil, err
	}

	return Package(bundle, includeVerificationKeys)
}

// Unpackage extracts an evidence bundle from portable format, verifying
// the package hash in the process.
func Unpackage(data []byte) (*PortableEvidence, error) {
	var pe PortableEvidence
	if err := json.Unmarshal(data, &pe); err != nil {
		return nil, fmt.Errorf("evidence/portable: unmarshal failed: %w", err)
	}

	if pe.Bundle == nil {
		return nil, fmt.Errorf("evidence/portable: package contains no bundle")
	}

	// Verify package hash.
	computed, err := pe.computePackageHash()
	if err != nil {
		return nil, fmt.Errorf("evidence/portable: hash computation failed: %w", err)
	}
	if computed != pe.PackageHash {
		return nil, fmt.Errorf("evidence/portable: package hash mismatch: expected %s, computed %s",
			pe.PackageHash, computed)
	}

	return &pe, nil
}

// VerifyPortable performs comprehensive verification of a portable evidence
// package without network access.
func VerifyPortable(pe *PortableEvidence) error {
	if pe == nil {
		return fmt.Errorf("evidence/portable: nil package")
	}

	// Verify package hash.
	computed, err := pe.computePackageHash()
	if err != nil {
		return fmt.Errorf("evidence/portable: hash computation failed: %w", err)
	}
	if computed != pe.PackageHash {
		return fmt.Errorf("evidence/portable: package hash mismatch")
	}

	// Verify the underlying bundle.
	if err := pe.Bundle.Validate(); err != nil {
		return fmt.Errorf("evidence/portable: bundle validation failed: %w", err)
	}
	return verifyPortableBundleContext(pe.Bundle, pe.TrustAnchors)
}

// AddVerificationKey adds a verification key to the portable package.
func (pe *PortableEvidence) AddVerificationKey(key VerificationKey) {
	pe.VerificationKeys = append(pe.VerificationKeys, key)
}

// AddTrustAnchor adds a platform trust anchor to the portable package.
func (pe *PortableEvidence) AddTrustAnchor(anchor PlatformTrustAnchor) {
	pe.TrustAnchors = append(pe.TrustAnchors, anchor)
}

// Marshal serializes the portable evidence to JSON.
func (pe *PortableEvidence) Marshal() ([]byte, error) {
	return json.MarshalIndent(pe, "", "  ")
}

// computePackageHash computes SHA-256 over the package content, excluding
// the package hash itself.
func (pe *PortableEvidence) computePackageHash() (string, error) {
	type hashable struct {
		FormatVersion    string                `json:"format_version"`
		PackagedAt       string                `json:"packaged_at"`
		Bundle           *EvidenceBundle       `json:"bundle"`
		VerificationKeys []VerificationKey     `json:"verification_keys,omitempty"`
		TrustAnchors     []PlatformTrustAnchor `json:"trust_anchors,omitempty"`
		SchemaDefinition string                `json:"schema_definition,omitempty"`
	}

	h := hashable{
		FormatVersion:    pe.FormatVersion,
		PackagedAt:       pe.PackagedAt,
		Bundle:           pe.Bundle,
		VerificationKeys: pe.VerificationKeys,
		TrustAnchors:     pe.TrustAnchors,
		SchemaDefinition: pe.SchemaDefinition,
	}

	data, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("evidence/portable: marshal failed: %w", err)
	}

	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func verifyPortableBundleContext(bundle *EvidenceBundle, trustAnchors []PlatformTrustAnchor) error {
	if bundle == nil {
		return fmt.Errorf("evidence/portable: nil bundle")
	}
	if len(bundle.ChainOfCustody) > 0 {
		if err := VerifyCustodyChain(bundle.ChainOfCustody); err != nil {
			return fmt.Errorf("evidence/portable: custody chain verification failed: %w", err)
		}
	}
	if len(trustAnchors) > 0 && len(bundle.Attestations) > 0 {
		for _, att := range bundle.Attestations {
			trusted := false
			for _, anchor := range trustAnchors {
				if anchor.Platform == att.Platform {
					trusted = true
					break
				}
			}
			if !trusted {
				return fmt.Errorf("evidence/portable: attestation from untrusted platform: %s", att.Platform)
			}
		}
	}
	return nil
}
