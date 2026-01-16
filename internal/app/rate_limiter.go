package app

import (
	"sync"
	"time"
)

type rateLimiter struct {
	mu    sync.Mutex
	store map[string][]time.Time
	limit int
	span  time.Duration
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{store: make(map[string][]time.Time), limit: 5, span: time.Minute}
}

func (r *rateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	window := now.Add(-r.span)
	times := r.store[key]
	var filtered []time.Time
	for _, t := range times {
		if t.After(window) {
			filtered = append(filtered, t)
		}
	}
	if len(filtered) >= r.limit {
		r.store[key] = filtered
		return false
	}
	filtered = append(filtered, now)
	r.store[key] = filtered
	return true
}
