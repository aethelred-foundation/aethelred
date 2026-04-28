package app

import (
	"sync"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

var appTestBech32ConfigOnce sync.Once

func configureAppTestBech32Prefixes() {
	appTestBech32ConfigOnce.Do(func() {
		cfg := sdk.GetConfig()
		cfg.SetBech32PrefixForAccount(AccountAddressPrefix, AccountAddressPrefix+"pub")
		cfg.SetBech32PrefixForValidator(AccountAddressPrefix+"valoper", AccountAddressPrefix+"valoperpub")
		cfg.SetBech32PrefixForConsensusNode(AccountAddressPrefix+"valcons", AccountAddressPrefix+"valconspub")
	})
}
