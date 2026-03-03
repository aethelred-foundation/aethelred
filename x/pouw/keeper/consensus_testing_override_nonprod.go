//go:build !production

package keeper

// SetConsensusThresholdForTesting allows tests to override the threshold.
// This method is intentionally excluded from production builds.
func (ch *ConsensusHandler) SetConsensusThresholdForTesting(threshold int) {
	ch.consensusThreshold = threshold
}
