package httpapi

import "testing"

func TestRateLimiterBurstThenRefill(t *testing.T) {
	// burst 2, 0 refill within the test window: third immediate request fails.
	rl := newRateLimiter(0.0001, 2)
	if !rl.allow("1.1.1.1") || !rl.allow("1.1.1.1") {
		t.Fatal("first two requests within burst should be allowed")
	}
	if rl.allow("1.1.1.1") {
		t.Fatal("third request should be throttled once burst is spent")
	}
	// A different IP has its own bucket.
	if !rl.allow("2.2.2.2") {
		t.Fatal("distinct IP should not share a bucket")
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	rl := newRateLimiter(0, 0)
	if rl.enabled() {
		t.Fatal("rps<=0 should disable limiting")
	}
	for i := 0; i < 100; i++ {
		if !rl.allow("1.1.1.1") {
			t.Fatal("disabled limiter must allow everything")
		}
	}
}
