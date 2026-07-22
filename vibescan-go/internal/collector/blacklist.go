package collector

import (
	"context"
	"sync"
	"time"

	"github.com/vibescan/vibescan-go/internal/store"
)

// BlacklistTTL is the fixed cache lifetime for served CIDRs (server.py:_BLACKLIST_TTL).
const BlacklistTTL = time.Hour

// BlacklistCache serves the enabled CIDR blacklist with hourly caching,
// mirroring server.py:_get_blacklist_cidrs.
type BlacklistCache struct {
	mongo *store.Mongo

	mu        sync.Mutex
	cached    []string
	fetchedAt time.Time
}

// NewBlacklistCache builds a cache backed by the given Mongo store.
func NewBlacklistCache(m *store.Mongo) *BlacklistCache {
	return &BlacklistCache{mongo: m}
}

// Get returns the current CIDR list, refreshing from MongoDB at most hourly and
// falling back to the default seed when the database is unavailable.
func (b *BlacklistCache) Get(ctx context.Context) []string {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.cached) > 0 && time.Since(b.fetchedAt) < BlacklistTTL {
		return b.cached
	}

	cidrs, err := b.mongo.ReadBlacklistCIDRs(ctx)
	if err == nil && len(cidrs) > 0 {
		b.cached = cidrs
		b.fetchedAt = time.Now()
		return cidrs
	}
	if len(b.cached) > 0 {
		return b.cached
	}
	return store.DefaultBlacklistSeed
}
