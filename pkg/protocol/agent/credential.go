package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Credential types
// ---------------------------------------------------------------------------

// CredentialType classifies the kind of verifiable credential.
type CredentialType int

const (
	// CapabilityCredential attests that the subject has a specific capability.
	CapabilityCredential CredentialType = iota

	// AuthorizationCredential grants the subject authorization for specific actions.
	AuthorizationCredential

	// DelegationCredential records a delegation of authority.
	DelegationCredential

	// AttestationCredential provides a hardware or software attestation.
	AttestationCredential

	// ComplianceCredential attests compliance with a regulatory framework.
	ComplianceCredential
)

// String returns the human-readable label for a CredentialType.
func (t CredentialType) String() string {
	switch t {
	case CapabilityCredential:
		return "Capability"
	case AuthorizationCredential:
		return "Authorization"
	case DelegationCredential:
		return "Delegation"
	case AttestationCredential:
		return "Attestation"
	case ComplianceCredential:
		return "Compliance"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// Claim
// ---------------------------------------------------------------------------

// Claim is a single assertion within a credential.
type Claim struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Source   string `json:"source,omitempty"`
	Verified bool   `json:"verified"`
}

// ---------------------------------------------------------------------------
// Credential proof
// ---------------------------------------------------------------------------

// CredentialProof contains the cryptographic proof for a credential.
type CredentialProof struct {
	// Type is the proof type (e.g., "EcdsaSecp256r1Signature2019").
	Type string `json:"type"`

	// Created is when the proof was created.
	Created time.Time `json:"created"`

	// VerificationMethod is the DID of the key used.
	VerificationMethod string `json:"verification_method"`

	// SignatureHex is the hex-encoded ECDSA signature.
	SignatureHex string `json:"signature"`
}

// ---------------------------------------------------------------------------
// AgentCredential
// ---------------------------------------------------------------------------

// AgentCredential is a verifiable credential issued to an agent.
type AgentCredential struct {
	// ID is the unique credential identifier.
	ID string `json:"id"`

	// Issuer is the DID of the issuing agent.
	Issuer string `json:"issuer"`

	// Subject is the DID of the subject agent.
	Subject string `json:"subject"`

	// Type classifies the credential.
	Type CredentialType `json:"type"`

	// Claims are the assertions in this credential.
	Claims []Claim `json:"claims"`

	// IssuedAt is when the credential was issued.
	IssuedAt time.Time `json:"issued_at"`

	// ExpiresAt is when the credential expires (zero means no expiration).
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// Revoked indicates whether the credential has been revoked.
	Revoked bool `json:"revoked"`

	// RevokedAt is when the credential was revoked (zero if not revoked).
	RevokedAt time.Time `json:"revoked_at,omitempty"`

	// Proof contains the cryptographic proof.
	Proof *CredentialProof `json:"proof,omitempty"`
}

// IsValid checks whether the credential is currently valid (not expired, not revoked).
func (c *AgentCredential) IsValid() bool {
	if c.Revoked {
		return false
	}
	if !c.ExpiresAt.IsZero() && time.Now().After(c.ExpiresAt) {
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Credential operations
// ---------------------------------------------------------------------------

// IssueCredential creates and signs a new verifiable credential.
func IssueCredential(_ context.Context, issuerKey *ecdsa.PrivateKey, issuerDID, subjectDID string, credType CredentialType, claims []Claim, ttl time.Duration) (*AgentCredential, error) {
	if issuerKey == nil {
		return nil, fmt.Errorf("issuer key cannot be nil")
	}
	if issuerDID == "" || subjectDID == "" {
		return nil, fmt.Errorf("issuer and subject DIDs are required")
	}
	if len(claims) == 0 {
		return nil, fmt.Errorf("at least one claim is required")
	}

	now := time.Now().UTC()
	cred := &AgentCredential{
		ID:       uuid.New().String(),
		Issuer:   issuerDID,
		Subject:  subjectDID,
		Type:     credType,
		Claims:   claims,
		IssuedAt: now,
	}

	if ttl > 0 {
		cred.ExpiresAt = now.Add(ttl)
	}

	// Sign the credential.
	proof, err := signCredential(cred, issuerKey, issuerDID)
	if err != nil {
		return nil, fmt.Errorf("signing credential: %w", err)
	}
	cred.Proof = proof

	return cred, nil
}

// VerifyCredential verifies the cryptographic proof on a credential.
func VerifyCredential(cred *AgentCredential, issuerPubKey *ecdsa.PublicKey) error {
	if cred == nil {
		return fmt.Errorf("credential cannot be nil")
	}
	if cred.Revoked {
		return fmt.Errorf("credential has been revoked")
	}
	if !cred.ExpiresAt.IsZero() && time.Now().After(cred.ExpiresAt) {
		return fmt.Errorf("credential has expired")
	}
	if cred.Proof == nil {
		return fmt.Errorf("credential has no proof")
	}
	if issuerPubKey == nil {
		return fmt.Errorf("issuer public key is required for verification")
	}

	// Recompute the credential hash.
	hash := computeCredentialHash(cred)

	// Decode signature.
	sigBytes, err := hex.DecodeString(cred.Proof.SignatureHex)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	// ECDSA signatures are (r, s) where each is 32 bytes for P-256.
	if len(sigBytes) != 64 {
		return fmt.Errorf("invalid signature length: expected 64, got %d", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	if !ecdsa.Verify(issuerPubKey, hash, r, s) {
		return fmt.Errorf("credential signature verification failed")
	}

	return nil
}

// RevokeCredential marks a credential as revoked in the given store.
func RevokeCredential(_ context.Context, store CredentialStore, credentialID string) error {
	if store == nil {
		return fmt.Errorf("credential store cannot be nil")
	}
	return store.Revoke(credentialID)
}

// ---------------------------------------------------------------------------
// CredentialStore interface
// ---------------------------------------------------------------------------

// CredentialStore defines the interface for credential persistence.
type CredentialStore interface {
	// Store persists a credential.
	Store(cred *AgentCredential) error

	// Get retrieves a credential by ID.
	Get(id string) (*AgentCredential, error)

	// ListBySubject returns all credentials for a subject DID.
	ListBySubject(subjectDID string) ([]*AgentCredential, error)

	// ListByIssuer returns all credentials issued by an issuer DID.
	ListByIssuer(issuerDID string) ([]*AgentCredential, error)

	// Revoke marks a credential as revoked.
	Revoke(id string) error
}

// ---------------------------------------------------------------------------
// In-memory credential store (for testing and development)
// ---------------------------------------------------------------------------

// MemoryCredentialStore is an in-memory implementation of CredentialStore.
type MemoryCredentialStore struct {
	mu    sync.RWMutex
	creds map[string]*AgentCredential
}

// NewMemoryCredentialStore creates a new in-memory credential store.
func NewMemoryCredentialStore() *MemoryCredentialStore {
	return &MemoryCredentialStore{
		creds: make(map[string]*AgentCredential),
	}
}

func (s *MemoryCredentialStore) Store(cred *AgentCredential) error {
	if cred == nil {
		return fmt.Errorf("credential cannot be nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creds[cred.ID] = cred
	return nil
}

func (s *MemoryCredentialStore) Get(id string) (*AgentCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cred, ok := s.creds[id]
	if !ok {
		return nil, fmt.Errorf("credential %q not found", id)
	}
	return cred, nil
}

func (s *MemoryCredentialStore) ListBySubject(subjectDID string) ([]*AgentCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*AgentCredential
	for _, cred := range s.creds {
		if cred.Subject == subjectDID {
			result = append(result, cred)
		}
	}
	return result, nil
}

func (s *MemoryCredentialStore) ListByIssuer(issuerDID string) ([]*AgentCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*AgentCredential
	for _, cred := range s.creds {
		if cred.Issuer == issuerDID {
			result = append(result, cred)
		}
	}
	return result, nil
}

func (s *MemoryCredentialStore) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cred, ok := s.creds[id]
	if !ok {
		return fmt.Errorf("credential %q not found", id)
	}
	cred.Revoked = true
	cred.RevokedAt = time.Now().UTC()
	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func signCredential(cred *AgentCredential, key *ecdsa.PrivateKey, issuerDID string) (*CredentialProof, error) {
	hash := computeCredentialHash(cred)

	r, s, err := ecdsa.Sign(rand.Reader, key, hash)
	if err != nil {
		return nil, fmt.Errorf("ECDSA sign: %w", err)
	}

	// Encode r and s as fixed-length 32-byte big-endian values.
	sigBytes := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)

	return &CredentialProof{
		Type:               "EcdsaSecp256r1Signature2019",
		Created:            time.Now().UTC(),
		VerificationMethod: issuerDID,
		SignatureHex:       hex.EncodeToString(sigBytes),
	}, nil
}

func computeCredentialHash(cred *AgentCredential) []byte {
	data, _ := json.Marshal(struct {
		ID       string         `json:"id"`
		Issuer   string         `json:"issuer"`
		Subject  string         `json:"subject"`
		Type     CredentialType `json:"type"`
		Claims   []Claim        `json:"claims"`
		IssuedAt string         `json:"issued_at"`
	}{
		ID:       cred.ID,
		Issuer:   cred.Issuer,
		Subject:  cred.Subject,
		Type:     cred.Type,
		Claims:   cred.Claims,
		IssuedAt: cred.IssuedAt.Format(time.RFC3339Nano),
	})
	h := sha256.Sum256(data)
	return h[:]
}
