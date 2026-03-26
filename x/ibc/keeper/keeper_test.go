package keeper

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"cosmossdk.io/log"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/ibc/types"
)

// =============================================================================
// Test Helpers
// =============================================================================

// setupKeeper creates a fresh IBC Keeper backed by an in-memory KV store.
func setupKeeper(t *testing.T) (Keeper, sdk.Context) {
	t.Helper()

	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	tkey := storetypes.NewTransientStoreKey("transient_test")
	ctx := testutil.DefaultContext(storeKey, tkey)
	ctx = ctx.WithBlockTime(time.Now().UTC())
	ctx = ctx.WithBlockHeight(100)
	ctx = ctx.WithChainID("aethelred-test-1")

	ir := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(ir)
	storeService := runtime.NewKVStoreService(storeKey)

	k := NewKeeper(cdc, storeService, log.NewNopLogger(), "cosmos1authority")
	return k, ctx
}

// openChannel is a helper that stores an OPEN channel via OnChanOpenAck.
func openChannel(t *testing.T, k Keeper, ctx sdk.Context, channelID string) {
	t.Helper()
	err := k.OnChanOpenAck(ctx, channelID, types.PortID, "counterparty-chan-0", types.Version)
	require.NoError(t, err)
}

// validProofRelayPacketData returns a well-formed ProofRelayPacketData for testing.
func validProofRelayPacketData() *types.ProofRelayPacketData {
	outputHash := sha256.Sum256([]byte("test-output"))
	return &types.ProofRelayPacketData{
		PacketType:       types.PacketTypeProofRelay,
		JobID:            "job-001",
		ModelHash:        sha256.New().Sum(nil),
		InputHash:        sha256.New().Sum(nil),
		OutputHash:       outputHash[:],
		VerificationType: "tee",
		TEEAttestation: &types.TEEAttestationProof{
			Platform:    "aws-nitro",
			Quote:       []byte("test-quote"),
			UserData:    []byte("test-userdata"),
			Measurement: []byte("test-measurement"),
		},
		ConsensusEvidence: &types.ConsensusEvidencePacket{
			ValidatorCount: 3,
			TotalValidators: 4,
			AgreementPower: 75,
			TotalPower:     100,
		},
		SourceChainID: "source-chain-1",
		SourceHeight:  50,
	}
}

// validProofRelayBytes returns JSON-encoded valid proof relay packet data.
func validProofRelayBytes(t *testing.T) []byte {
	t.Helper()
	data := validProofRelayPacketData()
	b, err := json.Marshal(data)
	require.NoError(t, err)
	return b
}

// validProofRequestBytes returns JSON-encoded valid proof request packet data.
func validProofRequestBytes(t *testing.T) []byte {
	t.Helper()
	modelHash := sha256.Sum256([]byte("test-model"))
	req := types.ProofRequestPacketData{
		PacketType:           types.PacketTypeProofRequest,
		RequestID:            "req-001",
		ModelHash:            modelHash[:],
		InputHash:            sha256.New().Sum(nil),
		RequiredVerification: "tee",
		Callback: &types.CallbackInfo{
			ChannelId: "channel-0",
			PortId:    "aethelredproof",
		},
		SourceChainID: "requesting-chain-1",
	}
	b, err := json.Marshal(req)
	require.NoError(t, err)
	return b
}

// validSubscriptionBytes returns JSON-encoded valid subscription packet data.
func validSubscriptionBytes(t *testing.T, subID string, active bool) []byte {
	t.Helper()
	modelHash := sha256.Sum256([]byte("sub-model"))
	sub := types.ProofSubscriptionPacketData{
		PacketType:            types.PacketTypeProofSubscription,
		SubscriptionID:        subID,
		ModelHashes:           [][]byte{modelHash[:]},
		MinConsensusThreshold: 67,
		SourceChainID:         "subscriber-chain-1",
		Active:                active,
	}
	b, err := json.Marshal(sub)
	require.NoError(t, err)
	return b
}

// =============================================================================
// 1. Channel Lifecycle Tests
// =============================================================================

func TestOnChanOpenInit_ValidPort(t *testing.T) {
	k, ctx := setupKeeper(t)
	err := k.OnChanOpenInit(ctx, "channel-0", types.PortID, types.Version, "connection-0")
	require.NoError(t, err)
}

func TestOnChanOpenInit_InvalidPort(t *testing.T) {
	k, ctx := setupKeeper(t)
	err := k.OnChanOpenInit(ctx, "channel-0", "wrong-port", types.Version, "connection-0")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid port")
}

func TestOnChanOpenInit_EmptyVersionAccepted(t *testing.T) {
	k, ctx := setupKeeper(t)
	// Empty version is allowed (defaults to module version)
	err := k.OnChanOpenInit(ctx, "channel-0", types.PortID, "", "connection-0")
	require.NoError(t, err)
}

func TestOnChanOpenInit_InvalidVersion(t *testing.T) {
	k, ctx := setupKeeper(t)
	err := k.OnChanOpenInit(ctx, "channel-0", types.PortID, "wrong-version", "connection-0")
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrInvalidVersion)
}

func TestOnChanOpenTry_ValidCounterpartyVersion(t *testing.T) {
	k, ctx := setupKeeper(t)
	version, err := k.OnChanOpenTry(ctx, "channel-0", types.PortID, types.Version, "connection-0")
	require.NoError(t, err)
	require.Equal(t, types.Version, version)
}

func TestOnChanOpenTry_InvalidVersion(t *testing.T) {
	k, ctx := setupKeeper(t)
	_, err := k.OnChanOpenTry(ctx, "channel-0", types.PortID, "bad-version", "connection-0")
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrInvalidVersion)
}

func TestOnChanOpenTry_InvalidPort(t *testing.T) {
	k, ctx := setupKeeper(t)
	_, err := k.OnChanOpenTry(ctx, "channel-0", "wrong-port", types.Version, "connection-0")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid port")
}

func TestOnChanOpenAck_StoresChannelState(t *testing.T) {
	k, ctx := setupKeeper(t)

	err := k.OnChanOpenAck(ctx, "channel-0", types.PortID, "counterparty-chan-0", types.Version)
	require.NoError(t, err)

	// Verify channel state is stored as OPEN
	stateStr, err := k.Channels.Get(ctx, "channel-0")
	require.NoError(t, err)

	var state ChannelState
	require.NoError(t, json.Unmarshal([]byte(stateStr), &state))
	require.Equal(t, "OPEN", state.State)
	require.Equal(t, "channel-0", state.ChannelID)
	require.Equal(t, types.PortID, state.PortID)
	require.Equal(t, "counterparty-chan-0", state.CounterpartyChan)
	require.Equal(t, types.Version, state.Version)

	// Verify sequence counters initialized to 1
	seq, err := k.NextSequenceSend.Get(ctx, "channel-0")
	require.NoError(t, err)
	require.Equal(t, uint64(1), seq)

	recvSeq, err := k.NextSequenceRecv.Get(ctx, "channel-0")
	require.NoError(t, err)
	require.Equal(t, uint64(1), recvSeq)
}

func TestOnChanOpenAck_InvalidVersion(t *testing.T) {
	k, ctx := setupKeeper(t)
	err := k.OnChanOpenAck(ctx, "channel-0", types.PortID, "counterparty-chan-0", "bad-version")
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrInvalidVersion)
}

func TestOnChanOpenConfirm_StoresChannelState(t *testing.T) {
	k, ctx := setupKeeper(t)

	err := k.OnChanOpenConfirm(ctx, "channel-0", types.PortID)
	require.NoError(t, err)

	// Verify channel is stored as OPEN
	stateStr, err := k.Channels.Get(ctx, "channel-0")
	require.NoError(t, err)

	var state ChannelState
	require.NoError(t, json.Unmarshal([]byte(stateStr), &state))
	require.Equal(t, "OPEN", state.State)
	require.Equal(t, "channel-0", state.ChannelID)
	require.Equal(t, types.PortID, state.PortID)
	require.Equal(t, types.Version, state.Version)

	// Verify sequence counters
	seq, err := k.NextSequenceSend.Get(ctx, "channel-0")
	require.NoError(t, err)
	require.Equal(t, uint64(1), seq)
}

func TestOnChanCloseInit_AlwaysFails(t *testing.T) {
	k, ctx := setupKeeper(t)
	err := k.OnChanCloseInit(ctx, "channel-0", types.PortID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "channel close not allowed")
}

func TestOnChanCloseConfirm_MarksChannelClosed(t *testing.T) {
	k, ctx := setupKeeper(t)

	// First open the channel
	openChannel(t, k, ctx, "channel-0")

	// Now close it via counterparty confirm
	err := k.OnChanCloseConfirm(ctx, "channel-0", types.PortID)
	require.NoError(t, err)

	// Verify channel state is CLOSED
	stateStr, err := k.Channels.Get(ctx, "channel-0")
	require.NoError(t, err)

	var state ChannelState
	require.NoError(t, json.Unmarshal([]byte(stateStr), &state))
	require.Equal(t, "CLOSED", state.State)
}

func TestOnChanCloseConfirm_NonexistentChannel(t *testing.T) {
	k, ctx := setupKeeper(t)
	// Should not error for a nonexistent channel (graceful no-op)
	err := k.OnChanCloseConfirm(ctx, "nonexistent-channel", types.PortID)
	require.NoError(t, err)
}

// =============================================================================
// 2. Packet Handler Tests
// =============================================================================

func TestOnRecvPacket_ProofRelay_ValidPacket(t *testing.T) {
	k, ctx := setupKeeper(t)

	packetData := validProofRelayBytes(t)
	ackBytes, err := k.OnRecvPacket(ctx, packetData, "channel-0", 1)
	require.NoError(t, err)
	require.NotNil(t, ackBytes)

	// Verify ack contains success
	var ack ProofRelayAck
	require.NoError(t, json.Unmarshal(ackBytes, &ack))
	require.True(t, ack.Success)
	require.NotEmpty(t, ack.ProofID)

	// Verify proof record was stored
	_, err = k.RelayedProofs.Get(ctx, ack.ProofID)
	require.NoError(t, err)

	// Verify packet receipt was stored (dedup)
	receiptKey := fmt.Sprintf("%s/%d", "channel-0", 1)
	has, err := k.PacketReceipts.Has(ctx, receiptKey)
	require.NoError(t, err)
	require.True(t, has)
}

func TestOnRecvPacket_ProofRelay_Duplicate(t *testing.T) {
	k, ctx := setupKeeper(t)

	packetData := validProofRelayBytes(t)

	// First receive succeeds
	_, err := k.OnRecvPacket(ctx, packetData, "channel-0", 1)
	require.NoError(t, err)

	// Second receive with same channel/sequence is rejected as duplicate
	_, err = k.OnRecvPacket(ctx, packetData, "channel-0", 1)
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrDuplicateProof)
}

func TestOnRecvPacket_ProofRelay_DifferentSequenceAllowed(t *testing.T) {
	k, ctx := setupKeeper(t)

	packetData := validProofRelayBytes(t)

	// Sequence 1 succeeds
	_, err := k.OnRecvPacket(ctx, packetData, "channel-0", 1)
	require.NoError(t, err)

	// Sequence 2 with same data on same channel succeeds (different sequence)
	_, err = k.OnRecvPacket(ctx, packetData, "channel-0", 2)
	require.NoError(t, err)
}

func TestOnRecvPacket_ProofRequest_Valid(t *testing.T) {
	k, ctx := setupKeeper(t)

	packetData := validProofRequestBytes(t)
	ackBytes, err := k.OnRecvPacket(ctx, packetData, "channel-0", 1)
	require.NoError(t, err)
	require.NotNil(t, ackBytes)

	// Verify ack indicates acceptance
	var ack ProofRequestAck
	require.NoError(t, json.Unmarshal(ackBytes, &ack))
	require.True(t, ack.Accepted)
	require.Equal(t, "req-001", ack.RequestID)
}

func TestOnRecvPacket_Subscription_CreateAndStore(t *testing.T) {
	k, ctx := setupKeeper(t)

	packetData := validSubscriptionBytes(t, "sub-001", true)
	ackBytes, err := k.OnRecvPacket(ctx, packetData, "channel-0", 1)
	require.NoError(t, err)
	require.NotNil(t, ackBytes)

	// Verify ack
	var ack SubscriptionAck
	require.NoError(t, json.Unmarshal(ackBytes, &ack))
	require.True(t, ack.Success)
	require.Equal(t, "sub-001", ack.SubscriptionID)

	// Verify subscription was stored
	stateStr, err := k.Subscriptions.Get(ctx, "sub-001")
	require.NoError(t, err)

	var state SubscriptionState
	require.NoError(t, json.Unmarshal([]byte(stateStr), &state))
	require.Equal(t, "sub-001", state.SubscriptionID)
	require.Equal(t, "channel-0", state.ChannelID)
	require.Equal(t, "subscriber-chain-1", state.SourceChainID)
	require.True(t, state.Active)
	require.Equal(t, 67, state.MinConsensusThreshold)
	require.NotZero(t, state.CreatedAt)
}

func TestOnRecvPacket_Subscription_Unsubscribe(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Create active subscription
	_, err := k.OnRecvPacket(ctx, validSubscriptionBytes(t, "sub-002", true), "channel-0", 1)
	require.NoError(t, err)

	// Unsubscribe
	_, err = k.OnRecvPacket(ctx, validSubscriptionBytes(t, "sub-002", false), "channel-0", 2)
	require.NoError(t, err)

	// Verify subscription is now inactive
	stateStr, err := k.Subscriptions.Get(ctx, "sub-002")
	require.NoError(t, err)

	var state SubscriptionState
	require.NoError(t, json.Unmarshal([]byte(stateStr), &state))
	require.False(t, state.Active)
}

func TestOnRecvPacket_UnknownType_Fails(t *testing.T) {
	k, ctx := setupKeeper(t)

	packet := map[string]interface{}{
		"packet_type": "unknown_type",
		"job_id":      "job-999",
	}
	packetData, err := json.Marshal(packet)
	require.NoError(t, err)

	_, err = k.OnRecvPacket(ctx, packetData, "channel-0", 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown packet type")
}

func TestOnRecvPacket_InvalidJSON(t *testing.T) {
	k, ctx := setupKeeper(t)
	_, err := k.OnRecvPacket(ctx, []byte("not-json"), "channel-0", 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse packet type")
}

// =============================================================================
// 3. Outbound Relay Tests
// =============================================================================

func TestRelayProof_ValidChannel(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Open channel first
	openChannel(t, k, ctx, "channel-0")

	proofData := validProofRelayPacketData()
	seq, err := k.RelayProof(ctx, "channel-0", proofData)
	require.NoError(t, err)
	require.Equal(t, uint64(1), seq)

	// Verify source metadata was set
	require.Equal(t, "aethelred-test-1", proofData.SourceChainID)
	require.Equal(t, int64(100), proofData.SourceHeight)
}

func TestRelayProof_ClosedChannel_Fails(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Open then close channel
	openChannel(t, k, ctx, "channel-0")
	err := k.OnChanCloseConfirm(ctx, "channel-0", types.PortID)
	require.NoError(t, err)

	proofData := validProofRelayPacketData()
	_, err = k.RelayProof(ctx, "channel-0", proofData)
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrChannelClosed)
}

func TestRelayProof_NonexistentChannel_Fails(t *testing.T) {
	k, ctx := setupKeeper(t)

	proofData := validProofRelayPacketData()
	_, err := k.RelayProof(ctx, "channel-does-not-exist", proofData)
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrChannelNotFound)
}

func TestRelayProof_IncrementSequence(t *testing.T) {
	k, ctx := setupKeeper(t)
	openChannel(t, k, ctx, "channel-0")

	// First relay
	seq1, err := k.RelayProof(ctx, "channel-0", validProofRelayPacketData())
	require.NoError(t, err)
	require.Equal(t, uint64(1), seq1)

	// Second relay
	seq2, err := k.RelayProof(ctx, "channel-0", validProofRelayPacketData())
	require.NoError(t, err)
	require.Equal(t, uint64(2), seq2)

	// Third relay
	seq3, err := k.RelayProof(ctx, "channel-0", validProofRelayPacketData())
	require.NoError(t, err)
	require.Equal(t, uint64(3), seq3)

	// Verify next sequence is now 4
	nextSeq, err := k.NextSequenceSend.Get(ctx, "channel-0")
	require.NoError(t, err)
	require.Equal(t, uint64(4), nextSeq)
}

func TestRelayProof_StoresCommitment(t *testing.T) {
	k, ctx := setupKeeper(t)
	openChannel(t, k, ctx, "channel-0")

	proofData := validProofRelayPacketData()
	seq, err := k.RelayProof(ctx, "channel-0", proofData)
	require.NoError(t, err)

	// Verify packet commitment was stored
	commitKey := fmt.Sprintf("%s/%d", "channel-0", seq)
	commitment, err := k.PacketCommitments.Get(ctx, commitKey)
	require.NoError(t, err)
	require.Len(t, commitment, 32) // SHA-256 hash
}

func TestRelayProof_MultipleChannels(t *testing.T) {
	k, ctx := setupKeeper(t)

	openChannel(t, k, ctx, "channel-0")
	openChannel(t, k, ctx, "channel-1")

	// Relay on channel-0
	seq0, err := k.RelayProof(ctx, "channel-0", validProofRelayPacketData())
	require.NoError(t, err)
	require.Equal(t, uint64(1), seq0)

	// Relay on channel-1
	seq1, err := k.RelayProof(ctx, "channel-1", validProofRelayPacketData())
	require.NoError(t, err)
	require.Equal(t, uint64(1), seq1) // Independent sequence per channel

	// Second relay on channel-0
	seq0b, err := k.RelayProof(ctx, "channel-0", validProofRelayPacketData())
	require.NoError(t, err)
	require.Equal(t, uint64(2), seq0b)
}

// =============================================================================
// 4. Acknowledgement & Timeout Tests
// =============================================================================

func TestOnAcknowledgementPacket_Success(t *testing.T) {
	k, ctx := setupKeeper(t)
	openChannel(t, k, ctx, "channel-0")

	// Create a commitment first
	proofData := validProofRelayPacketData()
	seq, err := k.RelayProof(ctx, "channel-0", proofData)
	require.NoError(t, err)

	// Verify commitment exists
	commitKey := fmt.Sprintf("%s/%d", "channel-0", seq)
	_, err = k.PacketCommitments.Get(ctx, commitKey)
	require.NoError(t, err)

	// Process ack
	ack := ProofRelayAck{Success: true, ProofID: "proof-123"}
	ackBytes, _ := json.Marshal(ack)
	packetBytes, _ := proofData.Marshal()

	err = k.OnAcknowledgementPacket(ctx, packetBytes, ackBytes, "channel-0", seq)
	require.NoError(t, err)

	// Verify commitment was removed
	_, err = k.PacketCommitments.Get(ctx, commitKey)
	require.Error(t, err) // Should be gone
}

func TestOnTimeoutPacket_RemovesCommitment(t *testing.T) {
	k, ctx := setupKeeper(t)
	openChannel(t, k, ctx, "channel-0")

	proofData := validProofRelayPacketData()
	seq, err := k.RelayProof(ctx, "channel-0", proofData)
	require.NoError(t, err)

	commitKey := fmt.Sprintf("%s/%d", "channel-0", seq)
	_, err = k.PacketCommitments.Get(ctx, commitKey)
	require.NoError(t, err)

	// Process timeout
	packetBytes, _ := proofData.Marshal()
	err = k.OnTimeoutPacket(ctx, packetBytes, "channel-0", seq)
	require.NoError(t, err)

	// Verify commitment was removed
	_, err = k.PacketCommitments.Get(ctx, commitKey)
	require.Error(t, err)
}

// =============================================================================
// 5. Genesis Tests
// =============================================================================

func TestInitGenesis_StoresProofs(t *testing.T) {
	k, ctx := setupKeeper(t)

	gs := &types.GenesisState{
		Params: types.DefaultParams(),
		PortID: types.PortID,
		RelayedProofs: []*types.RelayedProofRecord{
			{
				ProofID:            "proof-abc",
				JobID:              "job-100",
				DestinationChainID: "dest-chain-1",
				ChannelID:          "channel-0",
				Sequence:           1,
				RelayedAtHeight:    50,
				Acknowledged:       true,
			},
			{
				ProofID:            "proof-def",
				JobID:              "job-101",
				DestinationChainID: "dest-chain-2",
				ChannelID:          "channel-1",
				Sequence:           2,
				RelayedAtHeight:    55,
				Acknowledged:       false,
			},
		},
	}

	k.InitGenesis(ctx, gs)

	// Verify proofs were stored
	proofStr, err := k.RelayedProofs.Get(ctx, "proof-abc")
	require.NoError(t, err)

	var record types.RelayedProofRecord
	require.NoError(t, json.Unmarshal([]byte(proofStr), &record))
	require.Equal(t, "proof-abc", record.ProofID)
	require.Equal(t, "job-100", record.JobID)
	require.True(t, record.Acknowledged)

	// Second proof
	proofStr2, err := k.RelayedProofs.Get(ctx, "proof-def")
	require.NoError(t, err)

	var record2 types.RelayedProofRecord
	require.NoError(t, json.Unmarshal([]byte(proofStr2), &record2))
	require.Equal(t, "proof-def", record2.ProofID)
	require.False(t, record2.Acknowledged)

	// Verify packet receipts were set for dedup
	has, err := k.PacketReceipts.Has(ctx, "proof-abc")
	require.NoError(t, err)
	require.True(t, has)

	has, err = k.PacketReceipts.Has(ctx, "proof-def")
	require.NoError(t, err)
	require.True(t, has)
}

func TestInitGenesis_EmptyProofs(t *testing.T) {
	k, ctx := setupKeeper(t)

	gs := &types.GenesisState{
		Params:        types.DefaultParams(),
		PortID:        types.PortID,
		RelayedProofs: []*types.RelayedProofRecord{},
	}

	// Should not panic with empty proofs
	k.InitGenesis(ctx, gs)
}

func TestExportGenesis_ReturnsDefaults(t *testing.T) {
	k, ctx := setupKeeper(t)

	gs := k.ExportGenesis(ctx)
	require.NotNil(t, gs)
	require.NotNil(t, gs.Params)
	require.Equal(t, types.PortID, gs.PortID)
	require.NotNil(t, gs.RelayedProofs)
	require.Len(t, gs.RelayedProofs, 0)

	// Verify default params
	require.Equal(t, 67, gs.Params.MinConsensusThreshold)
	require.Equal(t, 1024*1024, gs.Params.MaxRelayPacketSize)
}

// =============================================================================
// 6. Edge Cases: NotifySubscribers
// =============================================================================

func TestNotifySubscribers_MatchesModelHash(t *testing.T) {
	k, ctx := setupKeeper(t)

	// Open a channel for the subscriber
	openChannel(t, k, ctx, "channel-sub")

	// Create a subscription with a specific model hash
	targetModelHash := sha256.Sum256([]byte("target-model"))
	otherModelHash := sha256.Sum256([]byte("other-model"))

	sub := SubscriptionState{
		SubscriptionID:        "sub-filter",
		ChannelID:             "channel-sub",
		SourceChainID:         "sub-chain",
		ModelHashes:           [][]byte{targetModelHash[:]},
		MinConsensusThreshold: 50,
		Active:                true,
		CreatedAt:             time.Now().Unix(),
	}
	subJSON, _ := json.Marshal(sub)
	require.NoError(t, k.Subscriptions.Set(ctx, "sub-filter", string(subJSON)))

	// Send proof with matching model hash - should relay
	proofDataMatch := validProofRelayPacketData()
	proofDataMatch.ModelHash = targetModelHash[:]
	err := k.NotifySubscribers(ctx, proofDataMatch)
	require.NoError(t, err)

	// Verify a packet was committed (sequence advanced from 1 to 2)
	nextSeq, err := k.NextSequenceSend.Get(ctx, "channel-sub")
	require.NoError(t, err)
	require.Equal(t, uint64(2), nextSeq, "sequence should have advanced for matching model hash")

	// Send proof with non-matching model hash - should NOT relay
	proofDataNoMatch := validProofRelayPacketData()
	proofDataNoMatch.ModelHash = otherModelHash[:]
	err = k.NotifySubscribers(ctx, proofDataNoMatch)
	require.NoError(t, err)

	// Sequence should not have advanced
	nextSeq, err = k.NextSequenceSend.Get(ctx, "channel-sub")
	require.NoError(t, err)
	require.Equal(t, uint64(2), nextSeq, "sequence should NOT advance for non-matching model hash")
}

func TestNotifySubscribers_ConsensusThreshold(t *testing.T) {
	k, ctx := setupKeeper(t)

	openChannel(t, k, ctx, "channel-thresh")

	// Subscription requires 80% consensus
	sub := SubscriptionState{
		SubscriptionID:        "sub-thresh",
		ChannelID:             "channel-thresh",
		SourceChainID:         "thresh-chain",
		ModelHashes:           nil, // No model filter, accept all
		MinConsensusThreshold: 80,
		Active:                true,
		CreatedAt:             time.Now().Unix(),
	}
	subJSON, _ := json.Marshal(sub)
	require.NoError(t, k.Subscriptions.Set(ctx, "sub-thresh", string(subJSON)))

	// Proof with 90% consensus - should pass threshold
	proofHigh := validProofRelayPacketData()
	proofHigh.ConsensusEvidence = &types.ConsensusEvidencePacket{
		AgreementPower: 90,
		TotalPower:     100,
	}
	err := k.NotifySubscribers(ctx, proofHigh)
	require.NoError(t, err)

	nextSeq, err := k.NextSequenceSend.Get(ctx, "channel-thresh")
	require.NoError(t, err)
	require.Equal(t, uint64(2), nextSeq, "should relay proof with 90% consensus (threshold 80%)")

	// Proof with 70% consensus - should NOT pass threshold
	proofLow := validProofRelayPacketData()
	proofLow.ConsensusEvidence = &types.ConsensusEvidencePacket{
		AgreementPower: 70,
		TotalPower:     100,
	}
	err = k.NotifySubscribers(ctx, proofLow)
	require.NoError(t, err)

	nextSeq, err = k.NextSequenceSend.Get(ctx, "channel-thresh")
	require.NoError(t, err)
	require.Equal(t, uint64(2), nextSeq, "should NOT relay proof with 70% consensus (threshold 80%)")
}

func TestNotifySubscribers_InactiveSubscriptionSkipped(t *testing.T) {
	k, ctx := setupKeeper(t)

	openChannel(t, k, ctx, "channel-inactive")

	sub := SubscriptionState{
		SubscriptionID:        "sub-inactive",
		ChannelID:             "channel-inactive",
		SourceChainID:         "some-chain",
		MinConsensusThreshold: 0,
		Active:                false, // Inactive
		CreatedAt:             time.Now().Unix(),
	}
	subJSON, _ := json.Marshal(sub)
	require.NoError(t, k.Subscriptions.Set(ctx, "sub-inactive", string(subJSON)))

	proofData := validProofRelayPacketData()
	err := k.NotifySubscribers(ctx, proofData)
	require.NoError(t, err)

	// Sequence should remain at initial value (1) since inactive sub is skipped
	nextSeq, err := k.NextSequenceSend.Get(ctx, "channel-inactive")
	require.NoError(t, err)
	require.Equal(t, uint64(1), nextSeq, "inactive subscription should not trigger relay")
}

func TestNotifySubscribers_NoSubscriptions(t *testing.T) {
	k, ctx := setupKeeper(t)

	// No subscriptions exist - should not error
	proofData := validProofRelayPacketData()
	err := k.NotifySubscribers(ctx, proofData)
	require.NoError(t, err)
}

func TestNotifySubscribers_MultipleSubscribers(t *testing.T) {
	k, ctx := setupKeeper(t)

	openChannel(t, k, ctx, "channel-a")
	openChannel(t, k, ctx, "channel-b")

	// Two active subscriptions with no filters
	for _, id := range []string{"sub-a", "sub-b"} {
		chanID := "channel-a"
		if id == "sub-b" {
			chanID = "channel-b"
		}
		sub := SubscriptionState{
			SubscriptionID:        id,
			ChannelID:             chanID,
			SourceChainID:         "multi-chain",
			MinConsensusThreshold: 0,
			Active:                true,
			CreatedAt:             time.Now().Unix(),
		}
		subJSON, _ := json.Marshal(sub)
		require.NoError(t, k.Subscriptions.Set(ctx, id, string(subJSON)))
	}

	proofData := validProofRelayPacketData()
	err := k.NotifySubscribers(ctx, proofData)
	require.NoError(t, err)

	// Both channels should have advanced their sequence
	seqA, err := k.NextSequenceSend.Get(ctx, "channel-a")
	require.NoError(t, err)
	require.Equal(t, uint64(2), seqA)

	seqB, err := k.NextSequenceSend.Get(ctx, "channel-b")
	require.NoError(t, err)
	require.Equal(t, uint64(2), seqB)
}

// =============================================================================
// 7. Helper Function Tests
// =============================================================================

func TestComputeProofID_Deterministic(t *testing.T) {
	id1 := computeProofID("job-1", "chain-1", 1)
	id2 := computeProofID("job-1", "chain-1", 1)
	require.Equal(t, id1, id2, "same inputs must produce same proof ID")

	id3 := computeProofID("job-1", "chain-1", 2)
	require.NotEqual(t, id1, id3, "different sequence must produce different proof ID")

	id4 := computeProofID("job-2", "chain-1", 1)
	require.NotEqual(t, id1, id4, "different job ID must produce different proof ID")

	id5 := computeProofID("job-1", "chain-2", 1)
	require.NotEqual(t, id1, id5, "different chain must produce different proof ID")
}

func TestMatchesModelHash(t *testing.T) {
	hash1 := sha256.Sum256([]byte("model-1"))
	hash2 := sha256.Sum256([]byte("model-2"))
	hash3 := sha256.Sum256([]byte("model-3"))

	filters := [][]byte{hash1[:], hash2[:]}

	require.True(t, matchesModelHash(hash1[:], filters), "should match hash1")
	require.True(t, matchesModelHash(hash2[:], filters), "should match hash2")
	require.False(t, matchesModelHash(hash3[:], filters), "should not match hash3")

	// Empty target
	require.False(t, matchesModelHash(nil, filters), "nil target should not match")

	// Empty filters
	require.False(t, matchesModelHash(hash1[:], nil), "nil filters should not match")
	require.False(t, matchesModelHash(hash1[:], [][]byte{}), "empty filters should not match")
}

func TestGetAuthority(t *testing.T) {
	k, _ := setupKeeper(t)
	require.Equal(t, "cosmos1authority", k.GetAuthority())
}
