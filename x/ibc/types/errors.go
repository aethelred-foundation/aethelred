package types

import "errors"

// Sentinel errors for the IBC module
var (
	ErrInvalidSender    = errors.New("aethelredibc: invalid sender address")
	ErrInvalidChannel   = errors.New("aethelredibc: invalid channel ID")
	ErrInvalidPacket    = errors.New("aethelredibc: invalid packet data")
	ErrChannelNotFound  = errors.New("aethelredibc: channel not found")
	ErrChannelClosed    = errors.New("aethelredibc: channel is closed")
	ErrInvalidVersion   = errors.New("aethelredibc: invalid IBC version")
	ErrProofNotFound    = errors.New("aethelredibc: proof not found")
	ErrDuplicateProof   = errors.New("aethelredibc: duplicate proof relay")
	ErrInsufficientConsensus = errors.New("aethelredibc: insufficient consensus power for relay")
	ErrSubscriptionNotFound  = errors.New("aethelredibc: subscription not found")
	ErrInvalidProofType      = errors.New("aethelredibc: invalid proof type")
	ErrTimeout               = errors.New("aethelredibc: packet timed out")
)
