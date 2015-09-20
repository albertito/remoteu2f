package main

import (
	"sync"
	"time"
)

// Simple and trivial rate limiter.
// Only covers from gross mis-usage, this is not accurate or featureful.
type RateLimiter struct {
	Interval time.Duration
	MaxCount uint

	mu       sync.Mutex
	count    uint
	lastTick time.Time
}

func (r *RateLimiter) Allowed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if time.Since(r.lastTick) > r.Interval {
		r.lastTick = time.Now()
		r.count = 0
		return true
	}

	r.count++
	return r.count < r.MaxCount
}
