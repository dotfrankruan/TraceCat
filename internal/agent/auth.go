package agent

import (
	"crypto/sha256"
	"crypto/subtle"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// tokenStore holds the per-Agent inbound bearer token. Only SHA-256 digests
// are retained and compared in constant time; the token itself is never
// logged. The store starts empty in controller-enrollment mode (all inbound
// requests get 401 until enrollment succeeds) and is rotated atomically when a
// refresh returns a new token.
type tokenStore struct {
	mu       sync.RWMutex
	digest   [sha256.Size]byte
	enrolled bool
}

func newTokenStore(token string) *tokenStore {
	store := &tokenStore{}
	if token != "" {
		store.setToken(token)
	}
	return store
}

// setToken atomically replaces the inbound trace token.
func (s *tokenStore) setToken(token string) {
	digest := sha256.Sum256([]byte(token))
	s.mu.Lock()
	s.digest = digest
	s.enrolled = true
	s.mu.Unlock()
}

// authorized verifies a bearer token in constant time against the current
// digest. An unenrolled store rejects every request.
func (s *tokenStore) authorized(r *http.Request) bool {
	header := r.Header.Get("Authorization")
	scheme, value, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}

	presented := sha256.Sum256([]byte(value))
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.enrolled {
		return false
	}
	return subtle.ConstantTimeCompare(s.digest[:], presented[:]) == 1
}

// remoteIP returns the TCP peer IP for rate limiting. Forwarding headers are
// deliberately ignored: the Agent has no trusted proxy configuration.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

// tokenBucket is a monotonic token bucket. It is not safe for concurrent use
// without its owner's lock.
type tokenBucket struct {
	tokens     float64
	last       time.Time
	ratePerSec float64
	capacity   float64
}

func newTokenBucket(ratePerSec, capacity float64, now time.Time) *tokenBucket {
	return &tokenBucket{
		tokens:     capacity,
		last:       now,
		ratePerSec: ratePerSec,
		capacity:   capacity,
	}
}

func (b *tokenBucket) allow(now time.Time) (bool, time.Duration) {
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(b.capacity, b.tokens+elapsed*b.ratePerSec)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	if b.ratePerSec <= 0 {
		return false, time.Minute
	}
	wait := (1 - b.tokens) / b.ratePerSec
	return false, time.Duration(wait * float64(time.Second))
}

const maxRateLimitEntries = 4096

// rateLimiter enforces both a global and a per-remote-IP token bucket, plus a
// bound on the number of tracked clients.
type rateLimiter struct {
	mu       sync.Mutex
	now      func() time.Time
	rate     float64
	capacity float64
	global   *tokenBucket
	clients  map[string]*tokenBucket
}

func newRateLimiter(requestsPerMinute, burst int) *rateLimiter {
	rate := float64(requestsPerMinute) / 60.0
	capacity := float64(burst)
	now := time.Now
	return &rateLimiter{
		now:      now,
		rate:     rate,
		capacity: capacity,
		global:   newTokenBucket(rate, capacity, now()),
		clients:  make(map[string]*tokenBucket),
	}
}

// allow consumes one request. The returned duration is the suggested
// Retry-After delay.
func (l *rateLimiter) allow(client string) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if ok, wait := l.global.allow(now); !ok {
		return false, wait
	}
	bucket, ok := l.clients[client]
	if !ok {
		if len(l.clients) >= maxRateLimitEntries {
			// Bound memory without tracking per-client state forever. Evict one
			// arbitrary entry; it regains its burst allowance on the next request.
			for key := range l.clients {
				delete(l.clients, key)
				break
			}
		}
		bucket = newTokenBucket(l.rate, l.capacity, now)
		l.clients[client] = bucket
	}
	if ok, wait := bucket.allow(now); !ok {
		return false, wait
	}
	return true, 0
}

func retryAfterSeconds(wait time.Duration) int {
	seconds := int(math.Ceil(wait.Seconds()))
	if seconds < 1 {
		return 1
	}
	return seconds
}

func rateLimitRetryAfterHeader(wait time.Duration) string {
	return strconv.Itoa(retryAfterSeconds(wait))
}
