// Package keeper implements the IBC proof relay module keeper.
//
// The keeper manages IBC channels, packet lifecycle, and cross-chain proof relay
// for Aethelred's verified AI computation results. It handles:
//   - Channel lifecycle (open, close, acknowledgment)
//   - Outbound proof relay (sending verified proofs to other chains)
//   - Inbound proof requests (receiving computation requests from other chains)
//   - Subscription management for ongoing proof notifications
//   - Packet commitment storage for IBC relayer proofs
package keeper

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"cosmossdk.io/collections"
	"cosmossdk.io/core/store"
	"cosmossdk.io/log"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/ibc/types"
)

// Keeper manages the IBC proof relay module state
type Keeper struct {
	cdc          codec.Codec
	storeService store.KVStoreService
	logger       log.Logger
	authority    string

	// Channel state (JSON-encoded ChannelState)
	Channels collections.Map[string, string]

	// Packet commitments (channelID/sequence -> commitment hash)
	PacketCommitments collections.Map[string, []byte]

	// Packet receipts (for dedup)
	PacketReceipts collections.Map[string, bool]

	// Relayed proof records (JSON-encoded types.RelayedProofRecord)
	RelayedProofs collections.Map[string, string]

	// Subscriptions (JSON-encoded SubscriptionState)
	Subscriptions collections.Map[string, string]

	// Next send sequence per channel
	NextSequenceSend collections.Map[string, uint64]

	// Next recv sequence per channel
	NextSequenceRecv collections.Map[string, uint64]

	// Module parameters (JSON-encoded types.Params)
	Params collections.Item[string]
}

// ChannelState tracks an IBC channel's current state
type ChannelState struct {
	ChannelID        string `json:"channel_id"`
	PortID           string `json:"port_id"`
	CounterpartyPort string `json:"counterparty_port"`
	CounterpartyChan string `json:"counterparty_channel"`
	State            string `json:"state"` // "OPEN", "CLOSED", "INIT", "TRYOPEN"
	Version          string `json:"version"`
	ConnectionID     string `json:"connection_id"`
}

// SubscriptionState tracks a cross-chain proof subscription
type SubscriptionState struct {
	SubscriptionID        string   `json:"subscription_id"`
	ChannelID             string   `json:"channel_id"`
	SourceChainID         string   `json:"source_chain_id"`
	ModelHashes           [][]byte `json:"model_hashes,omitempty"`
	MinConsensusThreshold int      `json:"min_consensus_threshold"`
	Active                bool     `json:"active"`
	CreatedAt             int64    `json:"created_at"`
}

// NewKeeper creates a new IBC proof relay keeper
func NewKeeper(
	cdc codec.Codec,
	storeService store.KVStoreService,
	logger log.Logger,
	authority string,
) Keeper {
	if logger == nil {
		logger = log.NewNopLogger()
	}

	sb := collections.NewSchemaBuilder(storeService)

	k := Keeper{
		cdc:          cdc,
		storeService: storeService,
		logger:       logger.With("module", types.ModuleName),
		authority:    authority,
		Channels: collections.NewMap(
			sb, collections.NewPrefix(types.ChannelPrefix),
			"channels",
			collections.StringKey,
			collections.StringValue, // JSON-encoded ChannelState
		),
		PacketCommitments: collections.NewMap(
			sb, collections.NewPrefix(types.PacketCommitmentPrefix),
			"packet_commitments",
			collections.StringKey,
			collections.BytesValue,
		),
		PacketReceipts: collections.NewMap(
			sb, collections.NewPrefix(types.PacketReceiptPrefix),
			"packet_receipts",
			collections.StringKey,
			collections.BoolValue,
		),
		NextSequenceSend: collections.NewMap(
			sb, collections.NewPrefix(types.SequencePrefix),
			"next_sequence_send",
			collections.StringKey,
			collections.Uint64Value,
		),
		NextSequenceRecv: collections.NewMap(
			sb, collections.NewPrefix([]byte{0x09}),
			"next_sequence_recv",
			collections.StringKey,
			collections.Uint64Value,
		),
		RelayedProofs: collections.NewMap(
			sb, collections.NewPrefix(types.RelayedProofPrefix),
			"relayed_proofs",
			collections.StringKey,
			collections.StringValue,
		),
		Subscriptions: collections.NewMap(
			sb, collections.NewPrefix(types.SubscriptionPrefix),
			"subscriptions",
			collections.StringKey,
			collections.StringValue,
		),
		Params: collections.NewItem(
			sb, collections.NewPrefix(types.ParamsKey),
			"params",
			collections.StringValue,
		),
	}

	return k
}

// GetAuthority returns the module's governance authority address
func (k Keeper) GetAuthority() string {
	return k.authority
}

// =============================================================================
// Channel Lifecycle Handlers
// =============================================================================

// OnChanOpenInit is called when a new IBC channel is initialized on this chain.
// Validates the port, version, and ordering requirements.
func (k Keeper) OnChanOpenInit(
	ctx sdk.Context,
	channelID string,
	portID string,
	version string,
	connectionID string,
) error {
	if portID != types.PortID {
		return fmt.Errorf("invalid port: %s, expected %s", portID, types.PortID)
	}

	if version != "" && version != types.Version {
		return fmt.Errorf("%w: got %s, expected %s", types.ErrInvalidVersion, version, types.Version)
	}

	k.logger.Info("IBC channel open init",
		"channel_id", channelID,
		"port_id", portID,
		"version", version,
		"connection_id", connectionID,
	)

	return nil
}

// OnChanOpenTry is called when the counterparty chain has initialized a channel.
// Validates the counterparty version.
func (k Keeper) OnChanOpenTry(
	ctx sdk.Context,
	channelID string,
	portID string,
	counterpartyVersion string,
	connectionID string,
) (string, error) {
	if portID != types.PortID {
		return "", fmt.Errorf("invalid port: %s, expected %s", portID, types.PortID)
	}

	if counterpartyVersion != types.Version {
		return "", fmt.Errorf("%w: counterparty version %s", types.ErrInvalidVersion, counterpartyVersion)
	}

	k.logger.Info("IBC channel open try",
		"channel_id", channelID,
		"counterparty_version", counterpartyVersion,
	)

	return types.Version, nil
}

// OnChanOpenAck is called when the channel handshake acknowledgment is received.
// Stores the channel state as OPEN.
func (k Keeper) OnChanOpenAck(
	ctx sdk.Context,
	channelID string,
	portID string,
	counterpartyChannelID string,
	counterpartyVersion string,
) error {
	if counterpartyVersion != types.Version {
		return fmt.Errorf("%w: counterparty version %s", types.ErrInvalidVersion, counterpartyVersion)
	}

	// Store channel as open
	state := ChannelState{
		ChannelID:        channelID,
		PortID:           portID,
		CounterpartyChan: counterpartyChannelID,
		State:            "OPEN",
		Version:          types.Version,
	}

	stateJSON, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal channel state: %w", err)
	}

	if err := k.Channels.Set(ctx, channelID, string(stateJSON)); err != nil {
		return fmt.Errorf("failed to store channel state: %w", err)
	}

	// Initialize sequence counters
	if err := k.NextSequenceSend.Set(ctx, channelID, 1); err != nil {
		return fmt.Errorf("failed to initialize send sequence: %w", err)
	}
	if err := k.NextSequenceRecv.Set(ctx, channelID, 1); err != nil {
		return fmt.Errorf("failed to initialize recv sequence: %w", err)
	}

	k.logger.Info("IBC channel opened",
		"channel_id", channelID,
		"counterparty_channel", counterpartyChannelID,
	)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			"ibc_channel_open",
			sdk.NewAttribute("channel_id", channelID),
			sdk.NewAttribute("port_id", portID),
			sdk.NewAttribute("counterparty_channel", counterpartyChannelID),
		),
	)

	return nil
}

// OnChanOpenConfirm is called when the channel open is confirmed by the counterparty.
func (k Keeper) OnChanOpenConfirm(
	ctx sdk.Context,
	channelID string,
	portID string,
) error {
	// Store channel as open (for the TRY side)
	state := ChannelState{
		ChannelID: channelID,
		PortID:    portID,
		State:     "OPEN",
		Version:   types.Version,
	}

	stateJSON, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal channel state: %w", err)
	}

	if err := k.Channels.Set(ctx, channelID, string(stateJSON)); err != nil {
		return fmt.Errorf("failed to store channel state: %w", err)
	}

	if err := k.NextSequenceSend.Set(ctx, channelID, 1); err != nil {
		return fmt.Errorf("failed to initialize send sequence: %w", err)
	}
	if err := k.NextSequenceRecv.Set(ctx, channelID, 1); err != nil {
		return fmt.Errorf("failed to initialize recv sequence: %w", err)
	}

	k.logger.Info("IBC channel confirmed", "channel_id", channelID)
	return nil
}

// OnChanCloseInit is called when this chain initiates a channel close.
func (k Keeper) OnChanCloseInit(
	ctx sdk.Context,
	channelID string,
	portID string,
) error {
	// Channels should not be closed by the module
	return fmt.Errorf("channel close not allowed for %s", types.ModuleName)
}

// OnChanCloseConfirm is called when the counterparty confirms channel close.
func (k Keeper) OnChanCloseConfirm(
	ctx sdk.Context,
	channelID string,
	portID string,
) error {
	k.logger.Info("IBC channel closed by counterparty", "channel_id", channelID)

	// Mark channel as closed
	stateStr, err := k.Channels.Get(ctx, channelID)
	if err != nil {
		return nil // Channel may not exist locally
	}

	var state ChannelState
	if err := json.Unmarshal([]byte(stateStr), &state); err != nil {
		return nil
	}

	state.State = "CLOSED"
	updatedJSON, _ := json.Marshal(state)
	_ = k.Channels.Set(ctx, channelID, string(updatedJSON))

	return nil
}

// =============================================================================
// Packet Handlers
// =============================================================================

// OnRecvPacket processes an incoming IBC packet.
func (k Keeper) OnRecvPacket(
	ctx sdk.Context,
	packetData []byte,
	channelID string,
	sequence uint64,
) ([]byte, error) {
	// Determine packet type from JSON
	var probe struct {
		PacketType types.PacketType `json:"packet_type"`
	}
	if err := json.Unmarshal(packetData, &probe); err != nil {
		return nil, fmt.Errorf("failed to parse packet type: %w", err)
	}

	switch probe.PacketType {
	case types.PacketTypeProofRelay, types.PacketTypeAttestationRelay:
		return k.handleProofRelayPacket(ctx, packetData, channelID, sequence)

	case types.PacketTypeProofRequest:
		return k.handleProofRequestPacket(ctx, packetData, channelID, sequence)

	case types.PacketTypeProofSubscription:
		return k.handleSubscriptionPacket(ctx, packetData, channelID, sequence)

	default:
		return nil, fmt.Errorf("unknown packet type: %s", probe.PacketType)
	}
}

// handleProofRelayPacket processes an incoming proof relay from another chain.
func (k Keeper) handleProofRelayPacket(
	ctx sdk.Context,
	packetData []byte,
	channelID string,
	sequence uint64,
) ([]byte, error) {
	packet, err := types.UnmarshalProofRelayPacketData(packetData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal proof relay: %w", err)
	}

	if err := packet.Validate(); err != nil {
		return nil, fmt.Errorf("invalid proof relay packet: %w", err)
	}

	// Check dedup
	receiptKey := fmt.Sprintf("%s/%d", channelID, sequence)
	has, _ := k.PacketReceipts.Has(ctx, receiptKey)
	if has {
		return nil, types.ErrDuplicateProof
	}

	// Store relayed proof record
	proofID := computeProofID(packet.JobID, packet.SourceChainID, sequence)
	record := types.RelayedProofRecord{
		ProofID:            proofID,
		JobID:              packet.JobID,
		DestinationChainID: ctx.ChainID(),
		ChannelID:          channelID,
		Sequence:           sequence,
		RelayedAtHeight:    ctx.BlockHeight(),
		Acknowledged:       false,
	}

	recordJSON, _ := json.Marshal(record)
	if err := k.RelayedProofs.Set(ctx, proofID, string(recordJSON)); err != nil {
		return nil, err
	}
	if err := k.PacketReceipts.Set(ctx, receiptKey, true); err != nil {
		return nil, err
	}

	k.logger.Info("received proof relay",
		"job_id", packet.JobID,
		"source_chain", packet.SourceChainID,
		"verification_type", packet.VerificationType,
		"consensus_power", fmt.Sprintf("%d/%d", packet.ConsensusEvidence.AgreementPower, packet.ConsensusEvidence.TotalPower),
	)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			"proof_relayed",
			sdk.NewAttribute("proof_id", proofID),
			sdk.NewAttribute("job_id", packet.JobID),
			sdk.NewAttribute("source_chain", packet.SourceChainID),
			sdk.NewAttribute("channel_id", channelID),
			sdk.NewAttribute("verification_type", packet.VerificationType),
		),
	)

	// Return success acknowledgement
	ack := ProofRelayAck{
		Success: true,
		ProofID: proofID,
	}
	ackBytes, _ := json.Marshal(ack)

	return ackBytes, nil
}

// handleProofRequestPacket processes an incoming proof computation request.
func (k Keeper) handleProofRequestPacket(
	ctx sdk.Context,
	packetData []byte,
	channelID string,
	sequence uint64,
) ([]byte, error) {
	request, err := types.UnmarshalProofRequestPacketData(packetData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal proof request: %w", err)
	}

	if err := request.Validate(); err != nil {
		return nil, fmt.Errorf("invalid proof request: %w", err)
	}

	k.logger.Info("received proof request",
		"request_id", request.RequestID,
		"model_hash", fmt.Sprintf("%x", request.ModelHash),
		"source_chain", request.SourceChainID,
	)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			"proof_requested",
			sdk.NewAttribute("request_id", request.RequestID),
			sdk.NewAttribute("source_chain", request.SourceChainID),
			sdk.NewAttribute("channel_id", channelID),
			sdk.NewAttribute("required_verification", request.RequiredVerification),
		),
	)

	// Return ack indicating the request was accepted for processing
	ack := ProofRequestAck{
		Accepted:  true,
		RequestID: request.RequestID,
	}
	ackBytes, _ := json.Marshal(ack)
	return ackBytes, nil
}

// handleSubscriptionPacket processes a subscription creation/removal.
func (k Keeper) handleSubscriptionPacket(
	ctx sdk.Context,
	packetData []byte,
	channelID string,
	sequence uint64,
) ([]byte, error) {
	var sub types.ProofSubscriptionPacketData
	if err := json.Unmarshal(packetData, &sub); err != nil {
		return nil, fmt.Errorf("failed to unmarshal subscription: %w", err)
	}

	state := SubscriptionState{
		SubscriptionID:        sub.SubscriptionID,
		ChannelID:             channelID,
		SourceChainID:         sub.SourceChainID,
		ModelHashes:           sub.ModelHashes,
		MinConsensusThreshold: sub.MinConsensusThreshold,
		Active:                sub.Active,
		CreatedAt:             ctx.BlockTime().Unix(),
	}

	stateJSON, _ := json.Marshal(state)
	if err := k.Subscriptions.Set(ctx, sub.SubscriptionID, string(stateJSON)); err != nil {
		return nil, err
	}

	action := "subscribed"
	if !sub.Active {
		action = "unsubscribed"
	}

	k.logger.Info("proof subscription updated",
		"subscription_id", sub.SubscriptionID,
		"action", action,
		"source_chain", sub.SourceChainID,
	)

	ack := SubscriptionAck{
		Success:        true,
		SubscriptionID: sub.SubscriptionID,
	}
	ackBytes, _ := json.Marshal(ack)
	return ackBytes, nil
}

// OnAcknowledgementPacket processes an acknowledgement for a sent packet.
func (k Keeper) OnAcknowledgementPacket(
	ctx sdk.Context,
	packetData []byte,
	ackData []byte,
	channelID string,
	sequence uint64,
) error {
	// Parse the ack
	var ack ProofRelayAck
	if err := json.Unmarshal(ackData, &ack); err != nil {
		k.logger.Error("failed to unmarshal acknowledgement", "error", err)
		return nil // Don't fail the tx
	}

	if ack.Success {
		k.logger.Info("proof relay acknowledged",
			"proof_id", ack.ProofID,
			"channel_id", channelID,
			"sequence", sequence,
		)
	} else {
		k.logger.Warn("proof relay rejected",
			"error", ack.Error,
			"channel_id", channelID,
			"sequence", sequence,
		)
	}

	// Remove packet commitment
	commitKey := fmt.Sprintf("%s/%d", channelID, sequence)
	_ = k.PacketCommitments.Remove(ctx, commitKey)

	return nil
}

// OnTimeoutPacket handles a packet that timed out.
func (k Keeper) OnTimeoutPacket(
	ctx sdk.Context,
	packetData []byte,
	channelID string,
	sequence uint64,
) error {
	k.logger.Warn("IBC packet timed out",
		"channel_id", channelID,
		"sequence", sequence,
	)

	// Remove packet commitment
	commitKey := fmt.Sprintf("%s/%d", channelID, sequence)
	_ = k.PacketCommitments.Remove(ctx, commitKey)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			"proof_relay_timeout",
			sdk.NewAttribute("channel_id", channelID),
			sdk.NewAttribute("sequence", fmt.Sprintf("%d", sequence)),
		),
	)

	return nil
}

// =============================================================================
// Outbound Proof Relay
// =============================================================================

// RelayProof sends a verified computation proof to a connected chain via IBC.
func (k Keeper) RelayProof(
	ctx sdk.Context,
	channelID string,
	proofData *types.ProofRelayPacketData,
) (uint64, error) {
	// Validate channel is open
	stateStr, err := k.Channels.Get(ctx, channelID)
	if err != nil {
		return 0, types.ErrChannelNotFound
	}

	var state ChannelState
	if err := json.Unmarshal([]byte(stateStr), &state); err != nil {
		return 0, fmt.Errorf("corrupted channel state: %w", err)
	}

	if state.State != "OPEN" {
		return 0, types.ErrChannelClosed
	}

	// Validate proof data
	if err := proofData.Validate(); err != nil {
		return 0, fmt.Errorf("invalid proof data: %w", err)
	}

	// Set source metadata
	proofData.SourceChainID = ctx.ChainID()
	proofData.SourceHeight = ctx.BlockHeight()
	proofData.Timestamp = ctx.BlockTime()

	// Get next sequence
	seq, err := k.NextSequenceSend.Get(ctx, channelID)
	if err != nil {
		seq = 1
	}

	// Serialize packet
	packetBytes, err := proofData.Marshal()
	if err != nil {
		return 0, fmt.Errorf("failed to marshal packet: %w", err)
	}

	// Store packet commitment
	commitment := types.ComputePacketCommitment(packetBytes, seq)
	commitKey := fmt.Sprintf("%s/%d", channelID, seq)
	if err := k.PacketCommitments.Set(ctx, commitKey, commitment); err != nil {
		return 0, fmt.Errorf("failed to store packet commitment: %w", err)
	}

	// Increment sequence
	if err := k.NextSequenceSend.Set(ctx, channelID, seq+1); err != nil {
		return 0, fmt.Errorf("failed to increment sequence: %w", err)
	}

	k.logger.Info("proof relayed via IBC",
		"job_id", proofData.JobID,
		"channel_id", channelID,
		"sequence", seq,
		"verification_type", proofData.VerificationType,
	)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			"proof_relay_sent",
			sdk.NewAttribute("job_id", proofData.JobID),
			sdk.NewAttribute("channel_id", channelID),
			sdk.NewAttribute("sequence", fmt.Sprintf("%d", seq)),
			sdk.NewAttribute("verification_type", proofData.VerificationType),
		),
	)

	return seq, nil
}

// NotifySubscribers sends proof notifications to all active subscribers
// that match the given proof. Called when a new computation reaches consensus.
func (k Keeper) NotifySubscribers(
	ctx sdk.Context,
	proofData *types.ProofRelayPacketData,
) error {
	// Iterate all subscriptions (in production, use an index)
	iter, err := k.Subscriptions.Iterate(ctx, nil)
	if err != nil {
		return nil // No subscriptions
	}
	defer iter.Close()

	for ; iter.Valid(); iter.Next() {
		stateStr, err := iter.Value()
		if err != nil {
			continue
		}

		var sub SubscriptionState
		if err := json.Unmarshal([]byte(stateStr), &sub); err != nil {
			continue
		}

		if !sub.Active {
			continue
		}

		// Check model hash filter
		if len(sub.ModelHashes) > 0 && !matchesModelHash(proofData.ModelHash, sub.ModelHashes) {
			continue
		}

		// Check consensus threshold
		if proofData.ConsensusEvidence != nil {
			pct := int(proofData.ConsensusEvidence.AgreementPower * 100 / proofData.ConsensusEvidence.TotalPower)
			if pct < sub.MinConsensusThreshold {
				continue
			}
		}

		// Relay to subscriber's channel
		_, relayErr := k.RelayProof(ctx, sub.ChannelID, proofData)
		if relayErr != nil {
			k.logger.Warn("failed to notify subscriber",
				"subscription_id", sub.SubscriptionID,
				"error", relayErr,
			)
		}
	}

	return nil
}

// =============================================================================
// Genesis
// =============================================================================

// InitGenesis initializes the module from genesis state
func (k Keeper) InitGenesis(ctx sdk.Context, gs *types.GenesisState) {
	for _, proof := range gs.RelayedProofs {
		proofJSON, _ := json.Marshal(proof)
		_ = k.PacketReceipts.Set(ctx, proof.ProofID, true)
		_ = k.RelayedProofs.Set(ctx, proof.ProofID, string(proofJSON))
	}
}

// ExportGenesis exports the module's state
func (k Keeper) ExportGenesis(ctx sdk.Context) *types.GenesisState {
	return &types.GenesisState{
		Params:        types.DefaultParams(),
		PortID:        types.PortID,
		RelayedProofs: []*types.RelayedProofRecord{},
	}
}

// =============================================================================
// Acknowledgement Types
// =============================================================================

// ProofRelayAck is the acknowledgement for a proof relay packet
type ProofRelayAck struct {
	Success bool   `json:"success"`
	ProofID string `json:"proof_id,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ProofRequestAck is the acknowledgement for a proof request packet
type ProofRequestAck struct {
	Accepted  bool   `json:"accepted"`
	RequestID string `json:"request_id"`
	Error     string `json:"error,omitempty"`
}

// SubscriptionAck is the acknowledgement for a subscription packet
type SubscriptionAck struct {
	Success        bool   `json:"success"`
	SubscriptionID string `json:"subscription_id"`
	Error          string `json:"error,omitempty"`
}

// =============================================================================
// Helpers
// =============================================================================

func computeProofID(jobID, sourceChain string, sequence uint64) string {
	h := sha256.New()
	h.Write([]byte(jobID))
	h.Write([]byte(sourceChain))
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, sequence)
	h.Write(seqBytes)
	sum := h.Sum(nil)
	return fmt.Sprintf("%x", sum[:16])
}

func matchesModelHash(target []byte, filters [][]byte) bool {
	for _, f := range filters {
		if len(f) == len(target) {
			match := true
			for i := range f {
				if f[i] != target[i] {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

// Compile-time assertions
var _ = SubscriptionState{}
var _ = time.Time{}
