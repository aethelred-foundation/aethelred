package types

import "fmt"

// GenesisState defines the IBC proof relay module's genesis state
type GenesisState struct {
	// Params are the module parameters
	Params *Params `json:"params"`

	// PortID is the IBC port to bind
	PortID string `json:"port_id"`

	// RelayedProofs are pre-existing relayed proof records
	RelayedProofs []*RelayedProofRecord `json:"relayed_proofs,omitempty"`
}

// Params defines the module parameters
type Params struct {
	// MinConsensusThreshold is the minimum consensus percentage required
	// for a proof to be relayed (0-100). Default: 67 (2/3 majority)
	MinConsensusThreshold int `json:"min_consensus_threshold"`

	// MaxRelayPacketSize is the maximum IBC packet size in bytes
	MaxRelayPacketSize int `json:"max_relay_packet_size"`

	// RelayFee is the fee charged for relaying a proof (in uaethel)
	RelayFee string `json:"relay_fee"`

	// AllowedVerificationTypes restricts which verification types can be relayed
	AllowedVerificationTypes []string `json:"allowed_verification_types"`

	// RequireBLSAggregate requires BLS aggregate signatures in consensus evidence
	RequireBLSAggregate bool `json:"require_bls_aggregate"`
}

// RelayedProofRecord stores a record of a successfully relayed proof
type RelayedProofRecord struct {
	// ProofID is the unique identifier
	ProofID string `json:"proof_id"`

	// JobID of the computation
	JobID string `json:"job_id"`

	// DestinationChainID where it was relayed
	DestinationChainID string `json:"destination_chain_id"`

	// ChannelID used for the relay
	ChannelID string `json:"channel_id"`

	// Sequence number of the IBC packet
	Sequence uint64 `json:"sequence"`

	// RelayedAtHeight on the source chain
	RelayedAtHeight int64 `json:"relayed_at_height"`

	// Acknowledged indicates if the destination confirmed receipt
	Acknowledged bool `json:"acknowledged"`
}

// DefaultGenesis returns the default genesis state
func DefaultGenesis() *GenesisState {
	return &GenesisState{
		Params:        DefaultParams(),
		PortID:        PortID,
		RelayedProofs: []*RelayedProofRecord{},
	}
}

// DefaultParams returns default module parameters
func DefaultParams() *Params {
	return &Params{
		MinConsensusThreshold:    67, // 2/3 majority
		MaxRelayPacketSize:       1024 * 1024, // 1MB
		RelayFee:                 "100uaethel",
		AllowedVerificationTypes: []string{"tee", "zkml", "hybrid"},
		RequireBLSAggregate:      false, // Can be enabled once all validators support BLS
	}
}

// Validate validates the genesis state
func (gs GenesisState) Validate() error {
	if gs.Params == nil {
		return fmt.Errorf("params cannot be nil")
	}
	if err := gs.Params.Validate(); err != nil {
		return fmt.Errorf("invalid params: %w", err)
	}
	if gs.PortID == "" {
		return fmt.Errorf("port ID cannot be empty")
	}
	for i, proof := range gs.RelayedProofs {
		if proof == nil {
			return fmt.Errorf("nil relayed proof at index %d", i)
		}
		if proof.ProofID == "" {
			return fmt.Errorf("empty proof ID at index %d", i)
		}
	}
	return nil
}

// Validate validates the params
func (p *Params) Validate() error {
	if p.MinConsensusThreshold < 1 || p.MinConsensusThreshold > 100 {
		return fmt.Errorf("consensus threshold must be between 1 and 100, got %d", p.MinConsensusThreshold)
	}
	if p.MaxRelayPacketSize <= 0 {
		return fmt.Errorf("max relay packet size must be positive")
	}
	return nil
}
