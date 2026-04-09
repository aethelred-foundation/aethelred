// Package agent implements the Agent Trust Protocol for the Aethelred platform.
// It provides verifiable agent identity (DID-based), delegated authority chains,
// machine-verifiable action receipts, and trust negotiation between agents.
//
// The protocol enables regulated enterprises to maintain full control and
// auditability over autonomous agent operations, including multi-hop delegation
// with depth limits and cryptographic verification at every step.
package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Agent DID (Decentralized Identifier)
// ---------------------------------------------------------------------------

// DIDMethod is the DID method name for Aethelred agents.
const DIDMethod = "aethelred"

// AgentDID represents a decentralized identifier for an agent.
type AgentDID struct {
	// Method is the DID method (always "aethelred").
	Method string `json:"method"`

	// ID is the unique identifier within the method namespace.
	ID string `json:"id"`

	// Fragment is an optional fragment for sub-resource identification.
	Fragment string `json:"fragment,omitempty"`
}

// String formats the DID as "did:aethelred:<id>[#fragment]".
func (d AgentDID) String() string {
	s := fmt.Sprintf("did:%s:%s", d.Method, d.ID)
	if d.Fragment != "" {
		s += "#" + d.Fragment
	}
	return s
}

// ParseDID parses a DID string of the form "did:aethelred:xxxx[#fragment]".
func ParseDID(didString string) (*AgentDID, error) {
	if didString == "" {
		return nil, fmt.Errorf("ParseDID: %w: DID string is empty", ErrInvalidInput)
	}
	if !strings.HasPrefix(didString, "did:") {
		return nil, fmt.Errorf("ParseDID: %w: must start with 'did:'", ErrInvalidInput)
	}

	parts := strings.SplitN(didString, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("ParseDID: %w: expected 'did:method:id'", ErrInvalidInput)
	}

	method := parts[1]
	if method != DIDMethod {
		return nil, fmt.Errorf("ParseDID: %w: unsupported DID method: %q (expected %q)", ErrInvalidInput, method, DIDMethod)
	}

	idAndFragment := parts[2]
	did := &AgentDID{Method: method}

	if idx := strings.Index(idAndFragment, "#"); idx >= 0 {
		did.ID = idAndFragment[:idx]
		did.Fragment = idAndFragment[idx+1:]
	} else {
		did.ID = idAndFragment
	}

	if did.ID == "" {
		return nil, fmt.Errorf("ParseDID: %w: empty ID", ErrInvalidInput)
	}

	// Validate fragment format if present (alphanumeric, hyphens, underscores).
	if did.Fragment != "" {
		for _, ch := range did.Fragment {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.') {
				return nil, fmt.Errorf("ParseDID: %w: invalid fragment character: %c", ErrInvalidInput, ch)
			}
		}
	}

	return did, nil
}

// FormatDID formats an AgentIdentity into a DID string.
func FormatDID(identity *AgentIdentity) string {
	if identity == nil || identity.DID == nil {
		return ""
	}
	return identity.DID.String()
}

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

// Capability represents a specific capability that an agent possesses.
type Capability struct {
	// Name is the capability identifier (e.g., "compute.execute", "model.deploy").
	Name string `json:"name"`

	// Version is the capability version.
	Version string `json:"version"`

	// Constraints are optional limits on the capability.
	Constraints map[string]string `json:"constraints,omitempty"`
}

// ---------------------------------------------------------------------------
// AgentIdentity
// ---------------------------------------------------------------------------

// AgentIdentity represents a verifiable agent identity in the Aethelred network.
type AgentIdentity struct {
	// DID is the decentralized identifier for this agent.
	DID *AgentDID `json:"did"`

	// PublicKey is the agent's ECDSA public key (P-256 curve).
	PublicKey *ecdsa.PublicKey `json:"-"`

	// PublicKeyHex is the hex-encoded compressed public key for serialization.
	PublicKeyHex string `json:"public_key"`

	// Capabilities lists what this agent can do.
	Capabilities []Capability `json:"capabilities"`

	// Issuer is the DID of whoever issued this identity (self for self-issued).
	Issuer string `json:"issuer"`

	// IssuedAt is when the identity was created.
	IssuedAt time.Time `json:"issued_at"`

	// ExpiresAt is when the identity expires (zero means no expiration).
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// Metadata holds arbitrary key-value pairs.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// NewAgentIdentity creates a new agent identity with a fresh ECDSA key pair.
// The identity is self-issued. Returns the identity and private key.
func NewAgentIdentity(capabilities []Capability) (*AgentIdentity, *ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating key pair: %w", err)
	}

	// Derive the DID from the public key hash.
	pubBytes := elliptic.MarshalCompressed(privateKey.PublicKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)
	h := sha256.Sum256(pubBytes)
	agentID := hex.EncodeToString(h[:16]) // Use first 16 bytes for a shorter ID.

	did := &AgentDID{
		Method: DIDMethod,
		ID:     agentID,
	}

	now := time.Now().UTC()
	identity := &AgentIdentity{
		DID:          did,
		PublicKey:     &privateKey.PublicKey,
		PublicKeyHex: hex.EncodeToString(pubBytes),
		Capabilities: capabilities,
		Issuer:       did.String(),
		IssuedAt:     now,
	}

	return identity, privateKey, nil
}

// NewAgentIdentityFromKey creates a new agent identity from an existing key pair.
func NewAgentIdentityFromKey(publicKey *ecdsa.PublicKey, capabilities []Capability) (*AgentIdentity, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}

	pubBytes := elliptic.MarshalCompressed(publicKey.Curve, publicKey.X, publicKey.Y)
	h := sha256.Sum256(pubBytes)
	agentID := hex.EncodeToString(h[:16])

	did := &AgentDID{
		Method: DIDMethod,
		ID:     agentID,
	}

	now := time.Now().UTC()
	identity := &AgentIdentity{
		DID:          did,
		PublicKey:     publicKey,
		PublicKeyHex: hex.EncodeToString(pubBytes),
		Capabilities: capabilities,
		Issuer:       did.String(),
		IssuedAt:     now,
	}

	return identity, nil
}

// VerifyIdentity verifies that an agent identity is well-formed and not expired.
func VerifyIdentity(identity *AgentIdentity) error {
	if identity == nil {
		return fmt.Errorf("VerifyIdentity: %w: identity cannot be nil", ErrInvalidInput)
	}
	if identity.DID == nil {
		return fmt.Errorf("VerifyIdentity: %w: identity DID cannot be nil", ErrIdentityInvalid)
	}
	if identity.DID.Method != DIDMethod {
		return fmt.Errorf("VerifyIdentity: %w: unsupported DID method: %q", ErrIdentityInvalid, identity.DID.Method)
	}
	if identity.DID.ID == "" {
		return fmt.Errorf("VerifyIdentity: %w: identity DID ID cannot be empty", ErrIdentityInvalid)
	}
	if identity.PublicKeyHex == "" {
		return fmt.Errorf("VerifyIdentity: %w: identity public key cannot be empty", ErrIdentityInvalid)
	}
	if identity.IssuedAt.IsZero() {
		return fmt.Errorf("VerifyIdentity: %w: identity issued_at cannot be zero", ErrIdentityInvalid)
	}
	if !identity.ExpiresAt.IsZero() && time.Now().After(identity.ExpiresAt) {
		return fmt.Errorf("VerifyIdentity: %w: identity has expired at %s", ErrCredentialExpired, identity.ExpiresAt)
	}

	// Verify the DID ID matches the public key hash.
	pubBytes, err := hex.DecodeString(identity.PublicKeyHex)
	if err != nil {
		return fmt.Errorf("invalid public key hex: %w", err)
	}
	h := sha256.Sum256(pubBytes)
	expectedID := hex.EncodeToString(h[:16])
	if identity.DID.ID != expectedID {
		return fmt.Errorf("DID ID does not match public key hash")
	}

	return nil
}

// HasCapability checks whether the identity has a specific capability.
func (id *AgentIdentity) HasCapability(name string) bool {
	for _, c := range id.Capabilities {
		if c.Name == name {
			return true
		}
	}
	return false
}

// AgentID returns the string form of the DID (convenience method).
func (id *AgentIdentity) AgentID() string {
	if id == nil || id.DID == nil {
		return ""
	}
	return id.DID.String()
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

// GenerateNonce returns a random hex-encoded nonce.
func GenerateNonce() string {
	return uuid.New().String()
}
