package server

import (
	"context"
	"sync"

	"github.com/kato83/mayu/internal/ingest"
)

// ingestRunner manages background ingest job execution with progress streaming.
// Only one job can run at a time (enforced by Server.ingestRunning).
type ingestRunner struct {
	mu       sync.RWMutex
	jobID    int64
	events   []ingestEvent
	done     bool
	// subscribers waiting for new events (signaled on each new event or completion)
	notify   chan struct{}
}

// newIngestRunner creates a runner for a specific job.
func newIngestRunner(jobID int64) *ingestRunner {
	return &ingestRunner{
		jobID:  jobID,
		events: make([]ingestEvent, 0, 64),
		notify: make(chan struct{}, 1),
	}
}

// appendEvent adds a progress event and notifies subscribers.
func (r *ingestRunner) appendEvent(evt ingestEvent) {
	r.mu.Lock()
	r.events = append(r.events, evt)
	r.mu.Unlock()
	r.signal()
}

// finish marks the runner as complete and notifies subscribers.
func (r *ingestRunner) finish() {
	r.mu.Lock()
	r.done = true
	r.mu.Unlock()
	r.signal()
}

// signal notifies any waiting subscribers that new data is available.
func (r *ingestRunner) signal() {
	select {
	case r.notify <- struct{}{}:
	default:
		// Channel already has a pending signal — no need to send another.
	}
}

// snapshot returns a copy of events starting from the given offset
// and whether the job is done.
func (r *ingestRunner) snapshot(offset int) ([]ingestEvent, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if offset >= len(r.events) {
		return nil, r.done
	}
	cp := make([]ingestEvent, len(r.events)-offset)
	copy(cp, r.events[offset:])
	return cp, r.done
}

// wait blocks until a signal (new event or finish) or context cancellation.
func (r *ingestRunner) wait(ctx context.Context) {
	select {
	case <-r.notify:
	case <-ctx.Done():
	}
}

// progressCallback returns an ingest.Progress callback that feeds events into this runner.
func (r *ingestRunner) progressCallback() func(ingest.Progress) {
	return func(p ingest.Progress) {
		r.appendEvent(ingestEvent{
			Phase:   p.Phase,
			Current: p.Current,
			Total:   p.Total,
			Message: p.Message,
		})
	}
}

// activeRunners tracks running/recently-completed ingest jobs so SSE clients
// can stream progress. Finished jobs are kept briefly for late-connecting clients.
type activeRunners struct {
	mu      sync.RWMutex
	current *ingestRunner
}

// start registers a new active runner, replacing any previous one.
func (a *activeRunners) start(r *ingestRunner) {
	a.mu.Lock()
	a.current = r
	a.mu.Unlock()
}

// get returns the current runner (may be nil or finished).
func (a *activeRunners) get() *ingestRunner {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.current
}

// getByID returns the runner only if it matches the given job ID.
func (a *activeRunners) getByID(jobID int64) *ingestRunner {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.current != nil && a.current.jobID == jobID {
		return a.current
	}
	return nil
}
