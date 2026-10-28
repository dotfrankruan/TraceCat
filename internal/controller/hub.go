package controller

import (
	"sync"

	"github.com/dotfrankruan/tracecat/internal/model"
)

// Hub fans complete job snapshots out to Server-Sent Events subscribers. It
// carries state-change notifications only: there is no per-probe streaming.
type Hub struct {
	mu   sync.Mutex
	subs map[string]map[chan model.Job]struct{}
}

// NewHub creates an empty hub.
func NewHub() *Hub {
	return &Hub{subs: make(map[string]map[chan model.Job]struct{})}
}

// Subscribe registers a subscriber for one job. The returned channel is closed
// when the job reaches a terminal state or the hub shuts down. The unsubscribe
// function is safe to call multiple times.
func (h *Hub) Subscribe(jobID string) (<-chan model.Job, func()) {
	ch := make(chan model.Job, 1)
	h.mu.Lock()
	set, ok := h.subs[jobID]
	if !ok {
		set = make(map[chan model.Job]struct{})
		h.subs[jobID] = set
	}
	set[ch] = struct{}{}
	h.mu.Unlock()

	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			h.mu.Lock()
			defer h.mu.Unlock()
			set, ok := h.subs[jobID]
			if !ok {
				return
			}
			if _, exists := set[ch]; !exists {
				return
			}
			delete(set, ch)
			close(ch)
			if len(set) == 0 {
				delete(h.subs, jobID)
			}
		})
	}
	return ch, unsubscribe
}

// Publish sends the latest snapshot to every subscriber of jobID. Slow
// subscribers keep only the newest snapshot (buffered channel of one).
func (h *Hub) Publish(jobID string, job model.Job) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[jobID] {
		select {
		case ch <- job:
		default:
			// Drop the stale snapshot, then store the newest one.
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- job:
			default:
			}
		}
	}
}

// Close terminates all subscriptions for a job.
func (h *Hub) Close(jobID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	set, ok := h.subs[jobID]
	if !ok {
		return
	}
	for ch := range set {
		close(ch)
	}
	delete(h.subs, jobID)
}

// CloseAll terminates every subscription (graceful shutdown).
func (h *Hub) CloseAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, set := range h.subs {
		for ch := range set {
			close(ch)
		}
		delete(h.subs, id)
	}
}
