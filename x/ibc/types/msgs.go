package types

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Ensure messages implement sdk.Msg
var (
	_ sdk.Msg = &MsgRelayProof{}
	_ sdk.Msg = &MsgRequestProof{}
	_ sdk.Msg = &MsgSubscribeProofs{}
)

// =============================================================================
// MsgRelayProof - Relay a verified proof through IBC
// =============================================================================

// MsgRelayProof relays a verified computation proof to a connected chain.
type MsgRelayProof struct {
	// Sender is the account initiating the relay
	Sender string `json:"sender"`

	// ChannelID is the IBC channel to relay through
	ChannelID string `json:"channel_id"`

	// ProofData is the proof relay packet data
	ProofData *ProofRelayPacketData `json:"proof_data"`

	// TimeoutHeight is the block height on the destination chain after which
	// the packet times out (0 = no height timeout)
	TimeoutHeight uint64 `json:"timeout_height"`

	// TimeoutTimestamp is the timestamp after which the packet times out
	// (0 = no timestamp timeout)
	TimeoutTimestamp uint64 `json:"timeout_timestamp"`
}

func (m *MsgRelayProof) ProtoMessage()             {}
func (m *MsgRelayProof) Reset()                     { *m = MsgRelayProof{} }
func (m *MsgRelayProof) String() string              { return fmt.Sprintf("MsgRelayProof{sender=%s}", m.Sender) }
func (m *MsgRelayProof) XXX_MessageName() string     { return "aethelred.ibc.v1.MsgRelayProof" }

func (m *MsgRelayProof) ValidateBasic() error {
	if m.Sender == "" {
		return ErrInvalidSender
	}
	if m.ChannelID == "" {
		return ErrInvalidChannel
	}
	if m.ProofData == nil {
		return ErrInvalidPacket
	}
	return m.ProofData.Validate()
}

func (m *MsgRelayProof) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(m.Sender)
	return []sdk.AccAddress{addr}
}

// =============================================================================
// MsgRequestProof - Request a proof from Aethelred via IBC
// =============================================================================

// MsgRequestProof sends a proof request to Aethelred from an external chain.
type MsgRequestProof struct {
	Sender    string                  `json:"sender"`
	ChannelID string                  `json:"channel_id"`
	Request   *ProofRequestPacketData `json:"request"`
}

func (m *MsgRequestProof) ProtoMessage()             {}
func (m *MsgRequestProof) Reset()                     { *m = MsgRequestProof{} }
func (m *MsgRequestProof) String() string              { return fmt.Sprintf("MsgRequestProof{sender=%s}", m.Sender) }
func (m *MsgRequestProof) XXX_MessageName() string     { return "aethelred.ibc.v1.MsgRequestProof" }

func (m *MsgRequestProof) ValidateBasic() error {
	if m.Sender == "" {
		return ErrInvalidSender
	}
	if m.ChannelID == "" {
		return ErrInvalidChannel
	}
	if m.Request == nil {
		return ErrInvalidPacket
	}
	return m.Request.Validate()
}

func (m *MsgRequestProof) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(m.Sender)
	return []sdk.AccAddress{addr}
}

// =============================================================================
// MsgSubscribeProofs - Subscribe to proof notifications
// =============================================================================

// MsgSubscribeProofs creates or removes a subscription for proof notifications.
type MsgSubscribeProofs struct {
	Sender       string                       `json:"sender"`
	ChannelID    string                       `json:"channel_id"`
	Subscription *ProofSubscriptionPacketData `json:"subscription"`
}

func (m *MsgSubscribeProofs) ProtoMessage()             {}
func (m *MsgSubscribeProofs) Reset()                     { *m = MsgSubscribeProofs{} }
func (m *MsgSubscribeProofs) String() string              { return fmt.Sprintf("MsgSubscribeProofs{sender=%s}", m.Sender) }
func (m *MsgSubscribeProofs) XXX_MessageName() string     { return "aethelred.ibc.v1.MsgSubscribeProofs" }

func (m *MsgSubscribeProofs) ValidateBasic() error {
	if m.Sender == "" {
		return ErrInvalidSender
	}
	if m.ChannelID == "" {
		return ErrInvalidChannel
	}
	if m.Subscription == nil {
		return ErrInvalidPacket
	}
	return nil
}

func (m *MsgSubscribeProofs) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(m.Sender)
	return []sdk.AccAddress{addr}
}
