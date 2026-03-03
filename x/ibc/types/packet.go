package types

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"
)

// =============================================================================
// IBC Packet Definitions for Cross-Chain Proof Relay
// =============================================================================

// PacketType identifies the kind of IBC packet
type PacketType string

const (
	// PacketTypeProofRelay relays a verified computation proof to another chain
	PacketTypeProofRelay PacketType = "proof_relay"

	// PacketTypeProofRequest requests a computation proof from Aethelred
	PacketTypeProofRequest PacketType = "proof_request"

	// PacketTypeProofSubscription subscribes to ongoing proof notifications
	PacketTypeProofSubscription PacketType = "proof_subscription"

	// PacketTypeAttestationRelay relays a TEE attestation result
	PacketTypeAttestationRelay PacketType = "attestation_relay"
)

// ProofRelayPacketData is the IBC packet data for relaying verified computation
// proofs cross-chain. This allows other Cosmos chains to consume Aethelred's
// verified AI computation results with full cryptographic guarantees.
type ProofRelayPacketData struct {
	// PacketType identifies this as a proof relay
	PacketType PacketType `json:"packet_type"`

	// JobID of the computation that was verified
	JobID string `json:"job_id"`

	// ModelHash is the SHA-256 hash of the AI model
	ModelHash []byte `json:"model_hash"`

	// InputHash is the SHA-256 hash of the computation input
	InputHash []byte `json:"input_hash"`

	// OutputHash is the SHA-256 hash of the computation output
	OutputHash []byte `json:"output_hash"`

	// VerificationType indicates how the computation was verified
	VerificationType string `json:"verification_type"` // "tee", "zkml", "hybrid"

	// TEEAttestation contains the TEE attestation proof (if applicable)
	TEEAttestation *TEEAttestationProof `json:"tee_attestation,omitempty"`

	// ZKProof contains the zero-knowledge proof (if applicable)
	ZKProof *ZKProofPacket `json:"zk_proof,omitempty"`

	// ConsensusEvidence contains the validator consensus evidence
	ConsensusEvidence *ConsensusEvidencePacket `json:"consensus_evidence"`

	// SourceChainID is the chain where the computation was verified
	SourceChainID string `json:"source_chain_id"`

	// SourceHeight is the block height where consensus was reached
	SourceHeight int64 `json:"source_height"`

	// Timestamp when the proof was finalized
	Timestamp time.Time `json:"timestamp"`

	// Memo is an optional human-readable memo
	Memo string `json:"memo,omitempty"`
}

// TEEAttestationProof is defined in packet.pb.go (protobuf-generated).
// The canonical definition lives there with proper ProtoMessage() support.

// ZKProofPacket contains a zero-knowledge proof for cross-chain relay
type ZKProofPacket struct {
	// ProofSystem identifies the proof system (ezkl, groth16, halo2, plonk)
	ProofSystem string `json:"proof_system"`

	// Proof is the proof bytes
	Proof []byte `json:"proof"`

	// PublicInputs for proof verification
	PublicInputs []byte `json:"public_inputs"`

	// VerifyingKeyHash for verifier identification
	VerifyingKeyHash []byte `json:"verifying_key_hash"`

	// CircuitHash for circuit identification
	CircuitHash []byte `json:"circuit_hash"`
}

// ConsensusEvidencePacket contains validator consensus evidence for the proof
type ConsensusEvidencePacket struct {
	// ValidatorCount is the number of validators that agreed
	ValidatorCount int `json:"validator_count"`

	// TotalValidators is the total validator count
	TotalValidators int `json:"total_validators"`

	// AgreementPower is the voting power that agreed
	AgreementPower int64 `json:"agreement_power"`

	// TotalPower is the total voting power
	TotalPower int64 `json:"total_power"`

	// BLSAggregateSignature is the aggregated BLS signature (96 bytes)
	BLSAggregateSignature []byte `json:"bls_aggregate_signature,omitempty"`

	// BLSSignerPubKeys lists contributing validator public keys
	BLSSignerPubKeys [][]byte `json:"bls_signer_pub_keys,omitempty"`
}

// ProofRequestPacketData is used by external chains to request computation
// verification from Aethelred.
type ProofRequestPacketData struct {
	PacketType PacketType `json:"packet_type"`

	// RequestID uniquely identifies this request
	RequestID string `json:"request_id"`

	// ModelHash of the model to run
	ModelHash []byte `json:"model_hash"`

	// InputHash of the input data
	InputHash []byte `json:"input_hash"`

	// RequiredVerification specifies verification type (tee, zkml, hybrid)
	RequiredVerification string `json:"required_verification"`

	// Callback contains info for relaying the result back
	Callback *CallbackInfo `json:"callback"`

	// SourceChainID of the requesting chain
	SourceChainID string `json:"source_chain_id"`

	// Timeout after which the request expires
	TimeoutTimestamp time.Time `json:"timeout_timestamp"`
}

// CallbackInfo is defined in packet.pb.go (protobuf-generated).
// The canonical definition lives there with proper ProtoMessage() support.
// Note: protobuf uses ChannelId/PortId (camelCase), not ChannelID/PortID.

// ProofSubscriptionPacketData sets up an ongoing subscription for proof
// notifications from Aethelred.
type ProofSubscriptionPacketData struct {
	PacketType PacketType `json:"packet_type"`

	// SubscriptionID uniquely identifies this subscription
	SubscriptionID string `json:"subscription_id"`

	// ModelHashes to subscribe to (empty = all models)
	ModelHashes [][]byte `json:"model_hashes,omitempty"`

	// MinConsensusThreshold minimum consensus % required (0-100)
	MinConsensusThreshold int `json:"min_consensus_threshold"`

	// SourceChainID of the subscribing chain
	SourceChainID string `json:"source_chain_id"`

	// Active indicates if this is a subscribe or unsubscribe
	Active bool `json:"active"`
}

// =============================================================================
// Packet Validation
// =============================================================================

// Validate performs validation of a ProofRelayPacketData.
func (p *ProofRelayPacketData) Validate() error {
	if p.PacketType != PacketTypeProofRelay && p.PacketType != PacketTypeAttestationRelay {
		return fmt.Errorf("invalid packet type for proof relay: %s", p.PacketType)
	}
	if p.JobID == "" {
		return fmt.Errorf("missing job ID")
	}
	if len(p.OutputHash) != 32 {
		return fmt.Errorf("output hash must be 32 bytes")
	}
	if p.ConsensusEvidence == nil {
		return fmt.Errorf("missing consensus evidence")
	}
	if p.ConsensusEvidence.TotalPower <= 0 {
		return fmt.Errorf("invalid total power: %d", p.ConsensusEvidence.TotalPower)
	}
	if p.SourceChainID == "" {
		return fmt.Errorf("missing source chain ID")
	}
	if p.SourceHeight <= 0 {
		return fmt.Errorf("invalid source height: %d", p.SourceHeight)
	}

	// Verify at least one attestation type is present for successful verifications
	if p.VerificationType != "" {
		switch p.VerificationType {
		case "tee":
			if p.TEEAttestation == nil {
				return fmt.Errorf("TEE verification type requires attestation data")
			}
		case "zkml":
			if p.ZKProof == nil {
				return fmt.Errorf("zkML verification type requires proof data")
			}
		case "hybrid":
			if p.TEEAttestation == nil || p.ZKProof == nil {
				return fmt.Errorf("hybrid verification requires both TEE and ZK data")
			}
		default:
			return fmt.Errorf("unknown verification type: %s", p.VerificationType)
		}
	}

	return nil
}

// Validate validates a proof request.
func (p *ProofRequestPacketData) Validate() error {
	if p.PacketType != PacketTypeProofRequest {
		return fmt.Errorf("invalid packet type: %s", p.PacketType)
	}
	if p.RequestID == "" {
		return fmt.Errorf("missing request ID")
	}
	if len(p.ModelHash) != 32 {
		return fmt.Errorf("model hash must be 32 bytes")
	}
	if p.Callback == nil {
		return fmt.Errorf("missing callback info")
	}
	return nil
}

// =============================================================================
// Packet Serialization
// =============================================================================

// Marshal serializes packet data to bytes.
func (p *ProofRelayPacketData) Marshal() ([]byte, error) {
	return json.Marshal(p)
}

// UnmarshalProofRelayPacketData deserializes packet data from bytes.
func UnmarshalProofRelayPacketData(data []byte) (*ProofRelayPacketData, error) {
	var p ProofRelayPacketData
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal proof relay packet: %w", err)
	}
	return &p, nil
}

// Marshal serializes packet data to bytes.
func (p *ProofRequestPacketData) Marshal() ([]byte, error) {
	return json.Marshal(p)
}

// UnmarshalProofRequestPacketData deserializes packet data.
func UnmarshalProofRequestPacketData(data []byte) (*ProofRequestPacketData, error) {
	var p ProofRequestPacketData
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal proof request packet: %w", err)
	}
	return &p, nil
}

// =============================================================================
// Packet Commitment (for IBC proof generation)
// =============================================================================

// ComputePacketCommitment computes a deterministic commitment hash for a packet.
// This is stored on-chain and used by IBC relayers to generate inclusion proofs.
func ComputePacketCommitment(packetData []byte, sequence uint64) []byte {
	h := sha256.New()
	h.Write([]byte("aethelred_ibc_packet_v1:"))
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, sequence)
	h.Write(seqBytes)
	h.Write(packetData)
	sum := h.Sum(nil)
	return sum
}
