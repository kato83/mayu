package auth

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// LoginRateLimiter provides IP-based rate limiting for login attempts.
// It uses a simple token bucket approach: each IP gets a fixed number
// of attempts per window, with tokens replenished periodically.
type LoginRateLimiter struct {
	mu       sync.Mutex
	attempts map[string]*rateBucket
	max      int
	window   time.Duration
}

type rateBucket struct {
	count   int
	resetAt time.Time
}

// NewLoginRateLimiter creates a new rate limiter allowing max attempts per window.
func NewLoginRateLimiter(max int, window time.Duration) *LoginRateLimiter {
	rl := &LoginRateLimiter{
		attempts: make(map[string]*rateBucket),
		max:      max,
		window:   window,
	}
	// Start background cleanup every 5 minutes
	go rl.cleanup()
	return rl
}

// Allow checks if the given IP is allowed to make a login attempt.
func (rl *LoginRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.attempts[ip]
	if !exists || now.After(bucket.resetAt) {
		rl.attempts[ip] = &rateBucket{count: 1, resetAt: now.Add(rl.window)}
		return true
	}

	if bucket.count >= rl.max {
		return false
	}
	bucket.count++
	return true
}

// cleanup removes expired entries periodically to prevent memory leaks.
func (rl *LoginRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, bucket := range rl.attempts {
			if now.After(bucket.resetAt) {
				delete(rl.attempts, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// RateLimitLogin returns middleware that rate-limits login attempts by client IP.
// Allows max attempts per window. Returns 429 Too Many Requests when exceeded.
func RateLimitLogin(limiter *LoginRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			if !limiter.Allow(ip) {
				writeAuthError(w, http.StatusTooManyRequests, "too many login attempts, please try again later")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP extracts the client IP from the request, checking X-Forwarded-For
// and X-Real-IP headers before falling back to RemoteAddr.
func clientIP(r *http.Request) string {
	// Check X-Forwarded-For (first IP in the chain)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := len(xff); idx > 0 {
			// Take the first IP (client IP in a proxy chain)
			for i, c := range xff {
				if c == ',' {
					return xff[:i]
				}
				_ = i
			}
			return xff
		}
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
