package translate

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiter_AllowBasic(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Max:    3,
		Window: 1 * time.Minute,
	})

	key := "user:1"

	// First 3 requests should be allowed
	for i := 0; i < 3; i++ {
		if !rl.Allow(key) {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	// 4th request should be denied
	if rl.Allow(key) {
		t.Fatal("4th request should be denied")
	}
}

func TestRateLimiter_DifferentKeysAreIndependent(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Max:    2,
		Window: 1 * time.Minute,
	})

	// Exhaust limit for user:1
	rl.Allow("user:1")
	rl.Allow("user:1")
	if rl.Allow("user:1") {
		t.Fatal("user:1 should be rate limited")
	}

	// user:2 should still be allowed
	if !rl.Allow("user:2") {
		t.Fatal("user:2 should be allowed (independent bucket)")
	}
}

func TestRateLimiter_WindowReset(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Max:    2,
		Window: 50 * time.Millisecond,
	})

	key := "user:1"

	// Exhaust limit
	rl.Allow(key)
	rl.Allow(key)
	if rl.Allow(key) {
		t.Fatal("should be rate limited")
	}

	// Wait for window to expire
	time.Sleep(60 * time.Millisecond)

	// Should be allowed again after window reset
	if !rl.Allow(key) {
		t.Fatal("should be allowed after window reset")
	}
}

func TestRateLimiter_BurstExceedsMax(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Max:    2,
		Window: 1 * time.Minute,
		Burst:  5,
	})

	key := "user:1"

	// Should allow up to burst (5) requests
	for i := 0; i < 5; i++ {
		if !rl.Allow(key) {
			t.Fatalf("request %d should be allowed (burst=5)", i+1)
		}
	}

	// 6th request should be denied
	if rl.Allow(key) {
		t.Fatal("6th request should be denied (burst=5)")
	}
}

func TestRateLimiter_BurstDefaultsToMax(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Max:    3,
		Window: 1 * time.Minute,
		Burst:  0, // Should default to Max
	})

	if rl.BurstLimit() != 3 {
		t.Fatalf("burst should default to max (3), got %d", rl.BurstLimit())
	}
}

func TestRateLimiter_DisabledWhenMaxIsZero(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Max:    0,
		Window: 1 * time.Minute,
	})

	if rl.Enabled() {
		t.Fatal("limiter should be disabled when Max=0")
	}

	// Should always allow
	for i := 0; i < 100; i++ {
		if !rl.Allow("user:1") {
			t.Fatalf("request %d should be allowed when disabled", i+1)
		}
	}
}

func TestRateLimiter_Remaining(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Max:    5,
		Window: 1 * time.Minute,
	})

	key := "user:1"

	// Before any requests
	remaining, _ := rl.Remaining(key)
	if remaining != 5 {
		t.Fatalf("expected 5 remaining before any requests, got %d", remaining)
	}

	// After 2 requests
	rl.Allow(key)
	rl.Allow(key)
	remaining, _ = rl.Remaining(key)
	if remaining != 3 {
		t.Fatalf("expected 3 remaining after 2 requests, got %d", remaining)
	}

	// After exhausting
	rl.Allow(key)
	rl.Allow(key)
	rl.Allow(key)
	remaining, _ = rl.Remaining(key)
	if remaining != 0 {
		t.Fatalf("expected 0 remaining after exhaustion, got %d", remaining)
	}
}

func TestRateLimiter_RemainingUnlimited(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Max:    0,
		Window: 1 * time.Minute,
	})

	remaining, _ := rl.Remaining("user:1")
	if remaining != -1 {
		t.Fatalf("expected -1 (unlimited) when disabled, got %d", remaining)
	}
}

func TestRateLimitMiddleware_AllowsRequests(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Max:    3,
		Window: 1 * time.Minute,
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})

	keyFunc := func(r *http.Request) string {
		return "test-user"
	}

	mw := RateLimitMiddleware(rl, keyFunc)(handler)

	// First 3 requests should succeed
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/translate", nil)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, req)

		if w.Code != http.StatusAccepted {
			t.Fatalf("request %d: expected 202, got %d", i+1, w.Code)
		}
		// Check rate limit headers are present
		if w.Header().Get("X-RateLimit-Limit") == "" {
			t.Fatalf("request %d: missing X-RateLimit-Limit header", i+1)
		}
		if w.Header().Get("X-RateLimit-Remaining") == "" {
			t.Fatalf("request %d: missing X-RateLimit-Remaining header", i+1)
		}
	}
}

func TestRateLimitMiddleware_Returns429WhenExceeded(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Max:    2,
		Window: 1 * time.Minute,
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})

	keyFunc := func(r *http.Request) string {
		return "test-user"
	}

	mw := RateLimitMiddleware(rl, keyFunc)(handler)

	// Exhaust the limit
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/translate", nil)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, req)
	}

	// 3rd request should get 429
	req := httptest.NewRequest(http.MethodPost, "/translate", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}

	// Check response contains error message
	body := w.Body.String()
	if body == "" {
		t.Fatal("expected error body in 429 response")
	}

	// Check Retry-After header is present
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After header in 429 response")
	}
}

func TestRateLimitMiddleware_DisabledPassesThrough(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Max:    0, // Disabled
		Window: 1 * time.Minute,
	})

	called := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	})

	keyFunc := func(r *http.Request) string {
		return "test-user"
	}

	mw := RateLimitMiddleware(rl, keyFunc)(handler)

	// Should always pass through when disabled
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodPost, "/translate", nil)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	if called != 50 {
		t.Fatalf("expected handler called 50 times, got %d", called)
	}
}

func TestClientIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")

	ip := ClientIP(req)
	if ip != "1.2.3.4" {
		t.Fatalf("expected 1.2.3.4, got %s", ip)
	}
}

func TestClientIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "10.0.0.1")

	ip := ClientIP(req)
	if ip != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1, got %s", ip)
	}
}

func TestClientIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	ip := ClientIP(req)
	if ip != "192.168.1.1" {
		t.Fatalf("expected 192.168.1.1, got %s", ip)
	}
}

func TestClientIP_SingleXForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "9.8.7.6")

	ip := ClientIP(req)
	if ip != "9.8.7.6" {
		t.Fatalf("expected 9.8.7.6, got %s", ip)
	}
}
