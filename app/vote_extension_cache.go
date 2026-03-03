package app

import (
	"encoding/hex"
	"fmt"
	"sort"
	"sync"

	abci "github.com/cometbft/cometbft/abci/types"
)

// VoteExtensionCache stores verified vote extensions by height and validator address.
//
// PRODUCTION SAFETY RULES (VC-01 through VC-05):
//
//   - VC-01: This cache is ADVISORY ONLY. ProcessProposal correctness must NOT
//     depend on cache presence. After a restart, the cache is empty and the chain
//     must continue without it.
//   - VC-02: When enforcement is needed, ProcessProposal must use req.VoteExtensions
//     (the consensus input), not this cache.
//   - VC-03: Cache keys include chainID + height to prevent cross-chain replay artifacts.
//   - VC-04: Fixed-size LRU by height window; bounded memory usage.
//   - VC-05: Only validated extensions are stored (caller must verify before Store).
type VoteExtensionCache struct {
	mu         sync.RWMutex
	byHeight   map[int64]map[string][]byte
	maxHeights int
	chainID    string // VC-03: Namespace to prevent cross-chain leakage.
}

// NewVoteExtensionCache creates a cache that retains at most maxHeights entries.
// The chainID parameter namespaces all cache entries to prevent cross-chain
// replay artifacts (VC-03).
func NewVoteExtensionCache(maxHeights int, chainID string) *VoteExtensionCache {
	if maxHeights <= 0 {
		maxHeights = 4
	}
	return &VoteExtensionCache{
		byHeight:   make(map[int64]map[string][]byte),
		maxHeights: maxHeights,
		chainID:    chainID,
	}
}

// Store records a verified vote extension for a validator at a given height.
//
// SECURITY (VC-05): The caller MUST only call Store AFTER the extension has
// been fully validated (unmarshal, signature verification, TEE schema checks,
// size bounds). Never call Store on unvalidated bytes.
func (c *VoteExtensionCache) Store(height int64, validatorAddr []byte, extension []byte) {
	if c == nil || height <= 0 || len(validatorAddr) == 0 {
		return
	}

	// VC-03: Include chainID in the cache key to prevent cross-chain leakage.
	key := c.cacheKey(validatorAddr)
	extCopy := make([]byte, len(extension))
	copy(extCopy, extension)

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.byHeight[height] == nil {
		c.byHeight[height] = make(map[string][]byte)
	}
	c.byHeight[height][key] = extCopy

	// VC-04: Enforce bounded memory via LRU pruning.
	c.prune()
}

// BuildExtendedVotes constructs ExtendedVoteInfo entries by combining commit votes
// with cached vote extensions for the given height.
//
// Returns the extended votes and the count of found cached extensions.
// When the cache is nil or empty (e.g. after restart), all extensions are nil
// and found == 0. Callers MUST handle found == 0 gracefully (VC-01).
func (c *VoteExtensionCache) BuildExtendedVotes(height int64, votes []abci.VoteInfo) ([]abci.ExtendedVoteInfo, int) {
	extended := make([]abci.ExtendedVoteInfo, 0, len(votes))
	if c == nil {
		for _, vote := range votes {
			extended = append(extended, abci.ExtendedVoteInfo{
				Validator:   vote.Validator,
				BlockIdFlag: vote.BlockIdFlag,
			})
		}
		return extended, 0
	}

	c.mu.RLock()
	byValidator := c.byHeight[height]
	c.mu.RUnlock()

	found := 0
	for _, vote := range votes {
		ext := []byte(nil)
		if byValidator != nil && len(vote.Validator.Address) > 0 {
			key := c.cacheKey(vote.Validator.Address)
			if cached, ok := byValidator[key]; ok {
				ext = cached
				found++
			}
		}
		extended = append(extended, abci.ExtendedVoteInfo{
			Validator:     vote.Validator,
			VoteExtension: ext,
			BlockIdFlag:   vote.BlockIdFlag,
		})
	}

	return extended, found
}

// EntryCount returns the total number of cached entries across all heights
// (for observability / memory monitoring).
func (c *VoteExtensionCache) EntryCount() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	total := 0
	for _, byVal := range c.byHeight {
		total += len(byVal)
	}
	return total
}

// cacheKey produces a namespaced cache key for a validator address.
// VC-03: Includes chainID to prevent cross-chain cache key collisions.
func (c *VoteExtensionCache) cacheKey(validatorAddr []byte) string {
	return fmt.Sprintf("%s:%s", c.chainID, hex.EncodeToString(validatorAddr))
}

func (c *VoteExtensionCache) prune() {
	if len(c.byHeight) <= c.maxHeights {
		return
	}

	heights := make([]int64, 0, len(c.byHeight))
	for h := range c.byHeight {
		heights = append(heights, h)
	}
	sort.Slice(heights, func(i, j int) bool { return heights[i] < heights[j] })

	for len(heights) > c.maxHeights {
		oldest := heights[0]
		delete(c.byHeight, oldest)
		heights = heights[1:]
	}
}
