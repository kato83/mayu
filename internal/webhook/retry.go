package webhook

import "time"

// Retry configuration constants.
const (
	// MaxRetryAttempts is the total number of delivery attempts (initial + retries).
	MaxRetryAttempts = 3
)

// retryDelays defines the backoff durations between retry attempts.
// Index 0 = delay after first failure, Index 1 = delay after second failure.
var retryDelays = []time.Duration{
	1 * time.Second,
	5 * time.Second,
	30 * time.Second,
}

// getRetryDelays returns the retry delay schedule.
// The returned slice has len >= MaxRetryAttempts-1 entries.
func getRetryDelays() []time.Duration {
	return retryDelays
}

// shouldRetry determines whether a delivery should be retried based on the
// HTTP status code and error. Returns true for 5xx responses and connection errors.
// Returns false for 2xx (success) and 4xx (client error) responses.
func shouldRetry(statusCode int, err error) bool {
	if err != nil {
		// Connection errors are retryable
		return true
	}
	// 5xx server errors are retryable
	if statusCode >= 500 {
		return true
	}
	// 2xx success and 4xx client errors are not retryable
	return false
}
