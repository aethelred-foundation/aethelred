// Package types defines the types and store keys for the Aethelred IBC module.
//
// This module implements Inter-Blockchain Communication (IBC) for cross-chain
// proof relay, enabling verified AI computation results (TEE attestations and
// ZK proofs) to be relayed to other Cosmos SDK chains with standardized
// security guarantees.
package types

const (
	// ModuleName is the name of the IBC proof relay module
	ModuleName = "aethelredibc"

	// StoreKey is the primary store key
	StoreKey = ModuleName

	// RouterKey is the message routing key
	RouterKey = ModuleName

	// QuerierRoute is the querier route
	QuerierRoute = ModuleName

	// MemStoreKey is the in-memory store key
	MemStoreKey = "mem_" + ModuleName

	// Version defines the current version of the IBC module
	Version = "aethelred-ibc-1"

	// PortID is the default port ID for the module
	PortID = "aethelredproof"
)

// Store key prefixes
var (
	// ChannelPrefix stores channel metadata
	ChannelPrefix = []byte{0x01}

	// PacketCommitmentPrefix stores packet commitments
	PacketCommitmentPrefix = []byte{0x02}

	// PacketReceiptPrefix stores packet receipts
	PacketReceiptPrefix = []byte{0x03}

	// PacketAckPrefix stores packet acknowledgements
	PacketAckPrefix = []byte{0x04}

	// RelayedProofPrefix stores relayed proof records
	RelayedProofPrefix = []byte{0x05}

	// SubscriptionPrefix stores cross-chain proof subscriptions
	SubscriptionPrefix = []byte{0x06}

	// ParamsKey stores module parameters
	ParamsKey = []byte{0x07}

	// SequencePrefix stores next send/recv sequences
	SequencePrefix = []byte{0x08}
)

// ChannelKey returns the store key for a channel
func ChannelKey(channelID string) []byte {
	return append(ChannelPrefix, []byte(channelID)...)
}

// PacketCommitmentKey returns the store key for a packet commitment
func PacketCommitmentKey(channelID string, sequence uint64) []byte {
	key := append(PacketCommitmentPrefix, []byte(channelID)...)
	key = append(key, '/')
	key = append(key, uint64ToBytes(sequence)...)
	return key
}

// RelayedProofKey returns the store key for a relayed proof record
func RelayedProofKey(proofID string) []byte {
	return append(RelayedProofPrefix, []byte(proofID)...)
}

// SubscriptionKey returns the store key for a subscription
func SubscriptionKey(subscriptionID string) []byte {
	return append(SubscriptionPrefix, []byte(subscriptionID)...)
}

func uint64ToBytes(v uint64) []byte {
	b := make([]byte, 8)
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
	return b
}
