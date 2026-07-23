package httpapi

import (
	"sync"
	"time"
)

// rateLimiter is a simple per-IP token-bucket limiter for the public read APIs.
// It is in-process (fine for the single-instance collector); a horizontally
// scaled deployment would move this to a shared store.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rps     float64 // tokens refilled per second
	burst   float64 // bucket capacity
}

type bucket struct {
	tokens float64
	last   time.Time // last refill
	seen   time.Time // last request (for eviction)
}

// newRateLimiter returns a limiter refilling rps tokens/sec up to burst. A
// non-positive rps disables limiting (allow always). It starts a background
// janitor that evicts idle buckets so the map can't grow without bound.
func newRateLimiter(rps, burst float64) *rateLimiter {
	rl := &rateLimiter{buckets: map[string]*bucket{}, rps: rps, burst: burst}
	if rps > 0 {
		go rl.janitor()
	}
	return rl
}

func (rl *rateLimiter) enabled() bool { return rl != nil && rl.rps > 0 }

// allow consumes one token for ip, returning false when the bucket is empty.
func (rl *rateLimiter) allow(ip string) bool {
	if !rl.enabled() {
		return true
	}
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b := rl.buckets[ip]
	if b == nil {
		b = &bucket{tokens: rl.burst, last: now}
		rl.buckets[ip] = b
	}
	// Refill proportional to elapsed time, capped at burst.
	b.tokens += now.Sub(b.last).Seconds() * rl.rps
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.last = now
	b.seen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// janitor periodically drops buckets idle long enough to have fully refilled,
// keeping memory bounded under churn from many distinct client IPs.
func (rl *rateLimiter) janitor() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-5 * time.Minute)
		rl.mu.Lock()
		for ip, b := range rl.buckets {
			if b.seen.Before(cutoff) {
				delete(rl.buckets, ip)
			}
		}
		rl.mu.Unlock()
	}
}
