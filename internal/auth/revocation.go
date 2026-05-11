package auth

import (
	"sync"
	"time"
)

const (
	DefaultRevocationTTL = 24 * time.Hour

	cleanupInterval = 30 * time.Minute
)

// Revocation holds blocked JWT IDs with automatic expiry.
type Revocation struct {
	mu      sync.RWMutex
	entries map[string]time.Time // jti -> expiry time
	stop    chan struct{}
}

// NewRevocation returns an empty revocation set and starts the cleanup loop.
func NewRevocation() *Revocation {
	r := &Revocation{
		entries: make(map[string]time.Time),
		stop:    make(chan struct{}),
	}
	go r.cleanupLoop()
	return r
}

// Close stops the background cleanup goroutine.
func (r *Revocation) Close() {
	close(r.stop)
}

// Block marks a jti as revoked for DefaultRevocationTTL.
func (r *Revocation) Block(jti string) {
	r.mu.Lock()
	r.entries[jti] = time.Now().Add(DefaultRevocationTTL)
	r.mu.Unlock()
}

// Unblock removes a jti from the revocation list.
func (r *Revocation) Unblock(jti string) {
	r.mu.Lock()
	delete(r.entries, jti)
	r.mu.Unlock()
}

// IsBlocked reports whether jti has been revoked and not yet expired.
func (r *Revocation) IsBlocked(jti string) bool {
	r.mu.RLock()
	exp, ok := r.entries[jti]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	// Lazily treat expired entry as not blocked.
	if time.Now().After(exp) {
		return false
	}
	return true
}

// List returns a snapshot of current non-expired blocked jti values.
func (r *Revocation) List() []string {
	now := time.Now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.entries))
	for k, exp := range r.entries {
		if now.Before(exp) {
			out = append(out, k)
		}
	}
	return out
}

// cleanupLoop periodically removes expired entries to free memory.
func (r *Revocation) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.sweep()
		}
	}
}

func (r *Revocation) sweep() {
	now := time.Now()
	r.mu.Lock()
	for jti, exp := range r.entries {
		if now.After(exp) {
			delete(r.entries, jti)
		}
	}
	r.mu.Unlock()
}
