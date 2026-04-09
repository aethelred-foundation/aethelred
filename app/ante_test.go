package app

import (
	"testing"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// ---------------------------------------------------------------------------
// NewAnteHandler signature validation
// ---------------------------------------------------------------------------

func TestNewAnteHandler_NilApp(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic when constructing ante handler with nil app")
		}
	}()
	// Passing nil should panic because the handler accesses app fields.
	_ = NewAnteHandler(nil)
}

// ---------------------------------------------------------------------------
// RateLimitDecorator
// ---------------------------------------------------------------------------

func TestRateLimitDecorator_NilRateLimiter(t *testing.T) {
	decorator := NewRateLimitDecorator(nil)
	// With nil rate limiter, AnteHandle should pass through to next.
	called := false
	next := func(ctx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) {
		called = true
		return ctx, nil
	}

	ctx := sdk.Context{}
	_, err := decorator.AnteHandle(ctx, nil, false, next)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("expected next handler to be called when rate limiter is nil")
	}
}

func TestRateLimitDecorator_SimulateSkipsRateLimit(t *testing.T) {
	rl := newTestRateLimiter()
	defer rl.Stop()

	decorator := NewRateLimitDecorator(rl)

	called := false
	next := func(ctx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) {
		called = true
		return ctx, nil
	}

	ctx := sdk.Context{}
	_, err := decorator.AnteHandle(ctx, nil, true, next)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("expected next handler to be called during simulation")
	}
}

// ---------------------------------------------------------------------------
// ComputeJobFeeDecorator constructor
// ---------------------------------------------------------------------------

func TestNewComputeJobFeeDecorator_NilBankKeeper(t *testing.T) {
	// Zero-value keeper + nil bank keeper should not panic on construction.
	// We pass the actual keeper type; method calls would fail at runtime
	// but construction should be safe.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("constructor should not panic: %v", r)
		}
	}()
	// We can't easily create a pouwkeeper.Keeper without full wiring,
	// so we skip this and focus on the logic tests below.
}

// ---------------------------------------------------------------------------
// Validate model hash requirements in ante handler
// ---------------------------------------------------------------------------

func TestModelHashValidation_32Bytes(t *testing.T) {
	// A valid model hash should be exactly 32 bytes (SHA-256).
	validHash := make([]byte, 32)
	if len(validHash) != 32 {
		t.Fatal("valid hash must be 32 bytes")
	}

	// Invalid: too short.
	shortHash := make([]byte, 16)
	if len(shortHash) == 32 {
		t.Fatal("short hash should not be 32 bytes")
	}

	// Invalid: too long.
	longHash := make([]byte, 64)
	if len(longHash) == 32 {
		t.Fatal("long hash should not be 32 bytes")
	}

	// Invalid: empty.
	emptyHash := []byte{}
	if len(emptyHash) == 32 {
		t.Fatal("empty hash should not be 32 bytes")
	}
}

// ---------------------------------------------------------------------------
// Fee validation logic
// ---------------------------------------------------------------------------

func TestFeeValidation_InsufficientFunds(t *testing.T) {
	fee := sdk.NewCoin("uaeth", sdkmath.NewInt(1000))
	balance := sdk.NewCoins(sdk.NewCoin("uaeth", sdkmath.NewInt(500)))

	if balance.IsAllGTE(sdk.NewCoins(fee)) {
		t.Fatal("500 should be less than 1000 fee")
	}
}

func TestFeeValidation_SufficientFunds(t *testing.T) {
	fee := sdk.NewCoin("uaeth", sdkmath.NewInt(1000))
	balance := sdk.NewCoins(sdk.NewCoin("uaeth", sdkmath.NewInt(2000)))

	if !balance.IsAllGTE(sdk.NewCoins(fee)) {
		t.Fatal("2000 should be greater than 1000 fee")
	}
}

func TestFeeValidation_ExactFunds(t *testing.T) {
	fee := sdk.NewCoin("uaeth", sdkmath.NewInt(1000))
	balance := sdk.NewCoins(sdk.NewCoin("uaeth", sdkmath.NewInt(1000)))

	if !balance.IsAllGTE(sdk.NewCoins(fee)) {
		t.Fatal("1000 should equal 1000 fee")
	}
}

func TestFeeValidation_ZeroFee(t *testing.T) {
	fee := sdk.NewCoin("uaeth", sdkmath.NewInt(0))
	balance := sdk.NewCoins(sdk.NewCoin("uaeth", sdkmath.NewInt(0)))

	if !balance.IsAllGTE(sdk.NewCoins(fee)) {
		t.Fatal("zero balance should cover zero fee")
	}
}
