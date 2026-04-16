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

// SponsorRecord captures one accountable sponsor in the passport chain for an
// enterprise-controlled agent identity.
type SponsorRecord struct {
	SponsorDID        string    `json:"sponsor_did"`
	SponsorName       string    `json:"sponsor_name,omitempty"`
	Jurisdiction      string    `json:"jurisdiction,omitempty"`
	Role              string    `json:"role,omitempty"`
	LiabilityAccepted bool      `json:"liability_accepted"`
	SignedAt          time.Time `json:"signed_at,omitempty"`
}

// LiabilityProfile captures the legal and operational accountability metadata
// that regulated enterprises need in order to use an agent in production.
type LiabilityProfile struct {
	HumanOwner       string `json:"human_owner"`
	BusinessUnit     string `json:"business_unit,omitempty"`
	SponsorOfRecord  string `json:"sponsor_of_record,omitempty"`
	FallbackApprover string `json:"fallback_approver,omitempty"`
	IncidentContact  string `json:"incident_contact,omitempty"`
	LiabilityModel   string `json:"liability_model,omitempty"`
}

// EnterpriseIdentityOptions configures an enterprise-grade agent passport.
type EnterpriseIdentityOptions struct {
	Issuer           string
	ExpiresAt        time.Time
	Metadata         map[string]string
	SponsorChain     []SponsorRecord
	Liability        *LiabilityProfile
	JurisdictionTags []string
	AllowedTools     []string
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

	// SponsorChain records the accountable entities that sponsor the agent.
	SponsorChain []SponsorRecord `json:"sponsor_chain,omitempty"`

	// Liability captures the human owner and operating accountability chain.
	Liability *LiabilityProfile `json:"liability,omitempty"`

	// JurisdictionTags declare where this agent is permitted to operate.
	JurisdictionTags []string `json:"jurisdiction_tags,omitempty"`

	// AllowedTools constrains the tools this passport authorizes directly.
	AllowedTools []string `json:"allowed_tools,omitempty"`

	// Metadata holds arbitrary key-value pairs.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// NewAgentIdentity creates a new agent identity with a fresh ECDSA key pair.
// The identity is self-issued. Returns the identity and private key.
func NewAgentIdentity(capabilities []Capability) (*AgentIdentity, *ecdsa.PrivateKey, error) {
	return NewEnterpriseAgentIdentity(capabilities, EnterpriseIdentityOptions{})
}

// NewEnterpriseAgentIdentity creates a new enterprise-grade agent identity
// with a fresh key pair and structured accountability metadata.
func NewEnterpriseAgentIdentity(capabilities []Capability, opts EnterpriseIdentityOptions) (*AgentIdentity, *ecdsa.PrivateKey, error) {
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
		DID:              did,
		PublicKey:        &privateKey.PublicKey,
		PublicKeyHex:     hex.EncodeToString(pubBytes),
		Capabilities:     capabilities,
		Issuer:           did.String(),
		IssuedAt:         now,
		ExpiresAt:        opts.ExpiresAt,
		SponsorChain:     normalizeSponsorChain(now, opts.SponsorChain),
		Liability:        cloneLiabilityProfile(opts.Liability),
		JurisdictionTags: cloneStringSlice(opts.JurisdictionTags),
		AllowedTools:     cloneStringSlice(opts.AllowedTools),
		Metadata:         cloneMetadata(opts.Metadata),
	}
	if opts.Issuer != "" {
		identity.Issuer = opts.Issuer
	}
	if identity.Liability != nil && identity.Liability.SponsorOfRecord == "" && len(identity.SponsorChain) > 0 {
		identity.Liability.SponsorOfRecord = identity.SponsorChain[0].SponsorDID
	}

	return identity, privateKey, nil
}

// NewAgentIdentityFromKey creates a new agent identity from an existing key pair.
func NewAgentIdentityFromKey(publicKey *ecdsa.PublicKey, capabilities []Capability) (*AgentIdentity, error) {
	return NewEnterpriseAgentIdentityFromKey(publicKey, capabilities, EnterpriseIdentityOptions{})
}

// NewEnterpriseAgentIdentityFromKey creates a new enterprise-grade agent
// identity from an existing public key.
func NewEnterpriseAgentIdentityFromKey(publicKey *ecdsa.PublicKey, capabilities []Capability, opts EnterpriseIdentityOptions) (*AgentIdentity, error) {
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
		DID:              did,
		PublicKey:        publicKey,
		PublicKeyHex:     hex.EncodeToString(pubBytes),
		Capabilities:     capabilities,
		Issuer:           did.String(),
		IssuedAt:         now,
		ExpiresAt:        opts.ExpiresAt,
		SponsorChain:     normalizeSponsorChain(now, opts.SponsorChain),
		Liability:        cloneLiabilityProfile(opts.Liability),
		JurisdictionTags: cloneStringSlice(opts.JurisdictionTags),
		AllowedTools:     cloneStringSlice(opts.AllowedTools),
		Metadata:         cloneMetadata(opts.Metadata),
	}
	if opts.Issuer != "" {
		identity.Issuer = opts.Issuer
	}
	if identity.Liability != nil && identity.Liability.SponsorOfRecord == "" && len(identity.SponsorChain) > 0 {
		identity.Liability.SponsorOfRecord = identity.SponsorChain[0].SponsorDID
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
	if !identity.ExpiresAt.IsZero() && identity.ExpiresAt.Before(identity.IssuedAt) {
		return fmt.Errorf("VerifyIdentity: %w: expires_at cannot be before issued_at", ErrIdentityInvalid)
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

	if err := verifyEnterprisePassport(identity); err != nil {
		return err
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

// HasJurisdiction reports whether the passport explicitly includes the given
// jurisdiction tag. An empty tag set means unrestricted.
func (id *AgentIdentity) HasJurisdiction(tag string) bool {
	if id == nil {
		return false
	}
	if len(id.JurisdictionTags) == 0 {
		return true
	}
	for _, candidate := range id.JurisdictionTags {
		if candidate == tag {
			return true
		}
	}
	return false
}

// AllowsTool reports whether the passport allows the given tool. An empty
// allowed-tool set means unrestricted.
func (id *AgentIdentity) AllowsTool(tool string) bool {
	if id == nil {
		return false
	}
	if len(id.AllowedTools) == 0 {
		return true
	}
	for _, candidate := range id.AllowedTools {
		if candidate == tool {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

// GenerateNonce returns a random hex-encoded nonce.
func GenerateNonce() string {
	return uuid.New().String()
}

func verifyEnterprisePassport(identity *AgentIdentity) error {
	for _, tag := range identity.JurisdictionTags {
		if strings.TrimSpace(tag) == "" {
			return fmt.Errorf("VerifyIdentity: %w: jurisdiction tag cannot be empty", ErrIdentityInvalid)
		}
	}
	for _, tool := range identity.AllowedTools {
		if strings.TrimSpace(tool) == "" {
			return fmt.Errorf("VerifyIdentity: %w: allowed tool cannot be empty", ErrIdentityInvalid)
		}
	}

	if len(identity.SponsorChain) > 0 {
		if identity.Liability == nil {
			return fmt.Errorf("VerifyIdentity: %w: liability profile required when sponsor chain is present", ErrIdentityInvalid)
		}
		seen := make(map[string]struct{}, len(identity.SponsorChain))
		for _, sponsor := range identity.SponsorChain {
			if strings.TrimSpace(sponsor.SponsorDID) == "" {
				return fmt.Errorf("VerifyIdentity: %w: sponsor DID cannot be empty", ErrIdentityInvalid)
			}
			if sponsor.SignedAt.IsZero() {
				return fmt.Errorf("VerifyIdentity: %w: sponsor signed_at cannot be zero", ErrIdentityInvalid)
			}
			if _, ok := seen[sponsor.SponsorDID]; ok {
				return fmt.Errorf("VerifyIdentity: %w: duplicate sponsor DID %q", ErrIdentityInvalid, sponsor.SponsorDID)
			}
			seen[sponsor.SponsorDID] = struct{}{}
		}
	}

	if identity.Liability != nil {
		if strings.TrimSpace(identity.Liability.HumanOwner) == "" {
			return fmt.Errorf("VerifyIdentity: %w: human owner is required for liability profile", ErrIdentityInvalid)
		}
		if len(identity.SponsorChain) > 0 && strings.TrimSpace(identity.Liability.SponsorOfRecord) == "" {
			return fmt.Errorf("VerifyIdentity: %w: sponsor_of_record is required when sponsor chain is present", ErrIdentityInvalid)
		}
	}

	return nil
}

func normalizeSponsorChain(now time.Time, in []SponsorRecord) []SponsorRecord {
	if len(in) == 0 {
		return nil
	}
	out := make([]SponsorRecord, len(in))
	copy(out, in)
	for i := range out {
		if out[i].SignedAt.IsZero() {
			out[i].SignedAt = now
		}
	}
	return out
}

func cloneLiabilityProfile(in *LiabilityProfile) *LiabilityProfile {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneMetadata(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneStringSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
