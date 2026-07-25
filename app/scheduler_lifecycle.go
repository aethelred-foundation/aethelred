package app

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// schedulePoUWJobsEndBlock activates jobs submitted in the current block and
// persists their validator assignments for the next height's ExtendVote.
// It must run after transaction delivery but before ModuleManager.EndBlock:
// staking's EndBlock updates are not applied by CometBFT until H+2, while these
// assignments are consumed by H+1 voters.
func (app *AethelredApp) schedulePoUWJobsEndBlock(ctx sdk.Context) error {
	if app.isPoUWAllocationHalted(ctx) {
		return nil
	}
	if app.consensusHandler == nil || app.consensusHandler.Scheduler() == nil {
		return fmt.Errorf("PoUW scheduler is not initialized")
	}
	selected, err := app.consensusHandler.Scheduler().ScheduleChainBacked(ctx)
	if err != nil {
		return fmt.Errorf("schedule chain-backed PoUW jobs: %w", err)
	}
	if len(selected) > 0 {
		app.Logger().Info(
			"PoUW jobs activated for vote extension",
			"height", ctx.BlockHeight(),
			"jobs", len(selected),
		)
	}
	return nil
}
