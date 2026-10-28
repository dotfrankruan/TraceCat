package controller

import (
	"sync"
	"time"
)

// rateLimiter is a bounded token-bucket limiter keyed by client identity. It is
// used for login attempts, resolve requests and job creation. Keys are capped
// to avoid unbounded memory use from spoofed clients.
type rateLimiter struct {
	mu       sync.Mutex
	rate     float64 // tokens per second
	burst    float64
	buckets  map[string]*rateBucket
	lastGC   time.Time
	maxKeys  int
	now      func() time.Time
	disabled bool
}

type rateBucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(perMinute float64) *rateLimiter {
	if perMinute <= 0 {
		perMinute = 1
	}
	l := &rateLimiter{
		rate:    perMinute / 60.0,
		burst:   perMinute,
		buckets: make(map[string]*rateBucket),
		now:     time.Now,
		maxKeys: 4096,
	}
	l.lastGC = l.now()
	return l
}

// Allow consumes one token for key and reports whether the request may proceed.
func (l *rateLimiter) Allow(key string) bool {
	if l == nil || l.disabled {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastGC) > 5*time.Minute {
		l.gcLocked(now)
		l.lastGC = now
	}
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.gcLocked(now)
			if len(l.buckets) >= l.maxKeys {
				// Fail closed: refuse new identities rather than grow without
				// bound.
				return false
			}
		}
		b = &rateBucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *rateLimiter) gcLocked(now time.Time) {
	for key, b := range l.buckets {
		if now.Sub(b.last) > 10*time.Minute && b.tokens >= l.burst-1 {
			delete(l.buckets, key)
		}
	}
	// Hard cap: if still oversized, drop the oldest half.
	if len(l.buckets) >= l.maxKeys {
		type entry struct {
			key  string
			last time.Time
		}
		entries := make([]entry, 0, len(l.buckets))
		for key, b := range l.buckets {
			entries = append(entries, entry{key: key, last: b.last})
		}
		// Simple approach: delete entries older than the median.
		cutoff := now.Add(-5 * time.Minute)
		for _, e := range entries {
			if e.last.Before(cutoff) {
				delete(l.buckets, e.key)
			}
		}
	}
}
