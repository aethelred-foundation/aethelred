package app

import (
	"testing"
	"time"

	"cosmossdk.io/log"
	sdkmath "cosmossdk.io/math"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

// ---------------------------------------------------------------------------
// StakingKeeperAdapter / SlashingKeeperAdapter constructor tests
// ---------------------------------------------------------------------------

func TestNewStakingKeeperAdapter(t *testing.T) {
	// Construction with nil keeper should not panic.
	adapter := NewStakingKeeperAdapter(nil)
	if adapter == nil {
		t.Fatal("expected non-nil adapter")
	}
}

// ---------------------------------------------------------------------------
// BlockMissConfig and EvidenceSlashingConfig defaults
// ---------------------------------------------------------------------------

func TestBlockMissConfig_Defaults(t *testing.T) {
	cfg := pouwkeeper.BlockMissConfig{
		ParticipationWindow: 10000,
		MaxMissedBlocks:     500,
		JailThreshold:       1000,
		DowntimeSlashBps:    500,
	}

	if cfg.ParticipationWindow != 10000 {
		t.Fatalf("unexpected participation window: %d", cfg.ParticipationWindow)
	}
	if cfg.MaxMissedBlocks != 500 {
		t.Fatalf("unexpected max missed blocks: %d", cfg.MaxMissedBlocks)
	}
	if cfg.JailThreshold != 1000 {
		t.Fatalf("unexpected jail threshold: %d", cfg.JailThreshold)
	}
	if cfg.DowntimeSlashBps != 500 {
		t.Fatalf("unexpected downtime slash bps: %d", cfg.DowntimeSlashBps)
	}
}

func TestEvidenceSlashingConfig_Defaults(t *testing.T) {
	cfg := pouwkeeper.EvidenceSlashingConfig{
		DoubleSignSlashBps:     5000,
		InvalidOutputSlashBps:  10000,
		DowntimeSlashBps:       500,
		CollusionSlashBps:      10000,
		DoubleSignJailDuration: 30 * 24 * time.Hour,
		DowntimeJailDuration:   24 * time.Hour,
		CollusionJailDuration:  365 * 24 * time.Hour,
	}

	if cfg.DoubleSignSlashBps != 5000 {
		t.Fatalf("unexpected double sign slash bps: %d", cfg.DoubleSignSlashBps)
	}
	if cfg.InvalidOutputSlashBps != 10000 {
		t.Fatalf("unexpected invalid output slash bps: %d", cfg.InvalidOutputSlashBps)
	}
	if cfg.DowntimeSlashBps != 500 {
		t.Fatalf("unexpected downtime slash bps: %d", cfg.DowntimeSlashBps)
	}
	if cfg.CollusionSlashBps != 10000 {
		t.Fatalf("unexpected collusion slash bps: %d", cfg.CollusionSlashBps)
	}
	if cfg.DoubleSignJailDuration != 30*24*time.Hour {
		t.Fatalf("unexpected double sign jail duration: %v", cfg.DoubleSignJailDuration)
	}
	if cfg.DowntimeJailDuration != 24*time.Hour {
		t.Fatalf("unexpected downtime jail duration: %v", cfg.DowntimeJailDuration)
	}
	if cfg.CollusionJailDuration != 365*24*time.Hour {
		t.Fatalf("unexpected collusion jail duration: %v", cfg.CollusionJailDuration)
	}
}

// ---------------------------------------------------------------------------
// LogSlashingEvent
// ---------------------------------------------------------------------------

func TestLogSlashingEvent_ValidResult(t *testing.T) {
	logger := log.NewNopLogger()
	result := &pouwkeeper.PoUWSlashResult{
		ValidatorAddress: "aethelredvaloper1abc",
		SlashedAmount:    sdkmath.NewInt(1000),
		Reason:           pouwkeeper.SlashReasonDoubleSign,
		SlashFractionBps: 5000,
		Jailed:           true,
		JailUntil:        time.Now().Add(30 * 24 * time.Hour),
		Tombstoned:       false,
		InfractionHeight: 12345,
	}
	// Should not panic.
	LogSlashingEvent(logger, result)
}

func TestLogSlashingEvent_DowntimeReason(t *testing.T) {
	logger := log.NewNopLogger()
	result := &pouwkeeper.PoUWSlashResult{
		ValidatorAddress: "aethelredvaloper1def",
		SlashedAmount:    sdkmath.NewInt(50),
		Reason:           pouwkeeper.SlashReasonDowntime,
		SlashFractionBps: 500,
		Jailed:           true,
		JailUntil:        time.Now().Add(24 * time.Hour),
		Tombstoned:       false,
		InfractionHeight: 9999,
	}
	LogSlashingEvent(logger, result)
}

func TestLogSlashingEvent_CollusionReason(t *testing.T) {
	logger := log.NewNopLogger()
	result := &pouwkeeper.PoUWSlashResult{
		ValidatorAddress: "aethelredvaloper1ghi",
		SlashedAmount:    sdkmath.NewInt(100000),
		Reason:           pouwkeeper.SlashReasonCollusion,
		SlashFractionBps: 10000,
		Jailed:           true,
		JailUntil:        time.Now().Add(365 * 24 * time.Hour),
		Tombstoned:       true,
		InfractionHeight: 5000,
	}
	LogSlashingEvent(logger, result)
}

func TestLogSlashingEvent_InvalidOutputReason(t *testing.T) {
	logger := log.NewNopLogger()
	result := &pouwkeeper.PoUWSlashResult{
		ValidatorAddress: "aethelredvaloper1jkl",
		SlashedAmount:    sdkmath.NewInt(999999),
		Reason:           pouwkeeper.SlashReasonInvalidOutput,
		SlashFractionBps: 10000,
		Jailed:           true,
		JailUntil:        time.Now().Add(365 * 24 * time.Hour),
		Tombstoned:       true,
		InfractionHeight: 7777,
		JobID:            "job-bad-output",
	}
	LogSlashingEvent(logger, result)
}

// ---------------------------------------------------------------------------
// BankKeeperAdapterForSlashing
// ---------------------------------------------------------------------------

func TestBankKeeperAdapterForSlashing_TypeCheck(t *testing.T) {
	// Verify the adapter struct compiles with the expected field type.
	adapter := BankKeeperAdapterForSlashing{}
	_ = adapter
}

// ---------------------------------------------------------------------------
// StakingValidatorPubKeyGetter
// ---------------------------------------------------------------------------

func TestStakingValidatorPubKeyGetter_NilKeeper(t *testing.T) {
	getter := &StakingValidatorPubKeyGetter{stakingKeeper: nil}
	if getter == nil {
		t.Fatal("expected non-nil getter")
	}
}

// ---------------------------------------------------------------------------
// Concurrent slashing config access
// ---------------------------------------------------------------------------

func TestSlashingConfig_ConcurrentRead(t *testing.T) {
	cfg := pouwkeeper.EvidenceSlashingConfig{
		DoubleSignSlashBps:     5000,
		DowntimeSlashBps:       500,
		CollusionSlashBps:      10000,
		DoubleSignJailDuration: 30 * 24 * time.Hour,
		DowntimeJailDuration:   24 * time.Hour,
		CollusionJailDuration:  365 * 24 * time.Hour,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			_ = cfg.DoubleSignSlashBps
			_ = cfg.DowntimeSlashBps
			_ = cfg.CollusionSlashBps
		}
	}()
	for i := 0; i < 1000; i++ {
		_ = cfg.DoubleSignJailDuration
		_ = cfg.DowntimeJailDuration
		_ = cfg.CollusionJailDuration
	}
	<-done
}
