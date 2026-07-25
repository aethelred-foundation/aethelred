package app

import (
	"context"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

type consensusValidatorResolver interface {
	GetValidatorByConsAddr(
		ctx context.Context,
		consAddr sdk.ConsAddress,
	) (stakingtypes.Validator, error)
}

func (app *AethelredApp) validatorByConsensusAddress(
	ctx sdk.Context,
	consAddr sdk.ConsAddress,
) (stakingtypes.Validator, error) {
	if app.consensusValidatorResolver != nil {
		return app.consensusValidatorResolver.GetValidatorByConsAddr(ctx, consAddr)
	}
	if app.StakingKeeper == nil {
		return stakingtypes.Validator{}, fmt.Errorf("staking keeper is not configured")
	}
	return app.StakingKeeper.GetValidatorByConsAddr(ctx, consAddr)
}
