package translate

import (
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	// DefaultRateLimit is the default maximum number of translation requests per window.
	// Each translation request corresponds to one CVE, so this allows translating
	// up to 20 CVEs per hour by default.
	DefaultRateLimit = 20
	// DefaultRateLimitWindow is the default window duration in seconds (1 hour).
	DefaultRateLimitWindow = 3600
)

// RateLimiterConfig holds the configuration for translation rate limiting.
type RateLimiterConfig struct {
	// Max is the maximum number of requests allowed per window.
	// 0 disables rate limiting.
	Max int
	// Window is the time window for the rate limit counter.
	Window time.Duration
	// Burst allows a short burst above the base rate. Must be >= Max.
	// If 0 or less than Max, it defaults to Max.
	Burst int
}

// RateLimiter provides user/IP-based rate limiting for translation requests.
// It uses a sliding-window token bucket approach: each key (user ID or IP)
// gets a fixed number of requests per window.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*translateBucket
	cfg     RateLimiterConfig
}

type translateBucket struct {
	count   int
	resetAt time.Time
}

// NewRateLimiter creates a new translation rate limiter with the given configuration.
// If cfg.Max is 0, the limiter is effectively disabled (Allow always returns true).
func NewRateLimiter(cfg RateLimiterConfig) *RateLimiter {
	if cfg.Burst < cfg.Max {
		cfg.Burst = cfg.Max
	}

	rl := &RateLimiter{
		buckets: make(map[string]*translateBucket),
		cfg:     cfg,
	}

	// Start background cleanup to prevent memory leaks from expired buckets.
	go rl.cleanup()
	return rl
}

// Enabled returns whether rate limiting is active.
func (rl *RateLimiter) Enabled() bool {
	return rl.cfg.Max > 0
}

// BurstLimit returns the configured burst limit.
func (rl *RateLimiter) BurstLimit() int {
	return rl.cfg.Burst
}

// Allow checks if the given key (user ID or IP) is allowed to make a translation request.
// Returns true if the request is allowed, false if rate limited.
func (rl *RateLimiter) Allow(key string) bool {
	if rl.cfg.Max <= 0 {
		return true // Rate limiting disabled
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.buckets[key]
	if !exists || now.After(bucket.resetAt) {
		// New window: reset counter
		rl.buckets[key] = &translateBucket{count: 1, resetAt: now.Add(rl.cfg.Window)}
		return true
	}

	if bucket.count >= rl.cfg.Burst {
		return false
	}
	bucket.count++
	return true
}

// Remaining returns the number of requests remaining for the given key in the current window.
// Returns (remaining, resetTime, exists).
func (rl *RateLimiter) Remaining(key string) (int, time.Time) {
	if rl.cfg.Max <= 0 {
		return -1, time.Time{} // Unlimited
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.buckets[key]
	if !exists || now.After(bucket.resetAt) {
		return rl.cfg.Burst, now.Add(rl.cfg.Window)
	}

	remaining := rl.cfg.Burst - bucket.count
	if remaining < 0 {
		remaining = 0
	}
	return remaining, bucket.resetAt
}

// cleanup removes expired entries periodically to prevent memory leaks.
func (rl *RateLimiter) cleanup() {
	// Cleanup interval is 1/6 of the window, minimum 1 minute.
	interval := rl.cfg.Window / 6
	if interval < time.Minute {
		interval = time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, bucket := range rl.buckets {
			if now.After(bucket.resetAt) {
				delete(rl.buckets, key)
			}
		}
		rl.mu.Unlock()
	}
}

// RateLimitMiddleware returns HTTP middleware that enforces translation rate limits.
// It extracts the rate limit key from the request context (user ID from auth)
// and falls back to client IP if no user is available.
//
// The keyFunc parameter extracts the rate limit key from the request.
// A typical implementation checks the auth context for a user ID or falls back to IP.
func RateLimitMiddleware(limiter *RateLimiter, keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Enabled() {
				next.ServeHTTP(w, r)
				return
			}

			key := keyFunc(r)
			if !limiter.Allow(key) {
				remaining, resetAt := limiter.Remaining(key)
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Header().Set("X-RateLimit-Limit", itoa(limiter.cfg.Burst))
				w.Header().Set("X-RateLimit-Remaining", itoa(remaining))
				w.Header().Set("X-RateLimit-Reset", formatUnix(resetAt))
				w.Header().Set("Retry-After", itoa(int(time.Until(resetAt).Seconds()+1)))
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"translation rate limit exceeded, please try again later"}`))
				return
			}

			// Set rate limit headers for successful requests too
			remaining, resetAt := limiter.Remaining(key)
			w.Header().Set("X-RateLimit-Limit", itoa(limiter.cfg.Burst))
			w.Header().Set("X-RateLimit-Remaining", itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", formatUnix(resetAt))

			next.ServeHTTP(w, r)
		})
	}
}

// ClientIP extracts the client IP from the request, checking X-Forwarded-For
// and X-Real-IP headers before falling back to RemoteAddr.
func ClientIP(r *http.Request) string {
	// Check X-Forwarded-For (first IP in the chain)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for i, c := range xff {
			if c == ',' {
				return xff[:i]
			}
			_ = i
		}
		return xff
	}

	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func itoa(n int) string {
	// Simple integer to string without importing strconv to keep the file self-contained
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + itoa(-n)
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	// reverse
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}

func formatUnix(t time.Time) string {
	return itoa(int(t.Unix()))
}
