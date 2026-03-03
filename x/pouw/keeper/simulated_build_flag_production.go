//go:build production

package keeper

func allowSimulatedInThisBuild() bool {
	return false
}
