package auth

import (
	"sync"
	"time"
)

// UserBan holds blocked JWT subjects (user IDs).
type UserBan struct {
	mu sync.RWMutex

	// I block each user in memory with expiry time
	// Real blocking process will be handled by java livestream --> If user is blocked, no gen jwt anymore
	entries map[string]time.Time
	stop    chan struct{}
}

// NewUserBan returns an empty user ban set.
func NewUserBan() *UserBan {
	u := &UserBan{
		entries: make(map[string]time.Time),
		stop:    make(chan struct{}),
	}
	go u.cleanupLoop()
	return u
}

// Block marks a subject as banned.
func (u *UserBan) Block(subject string) {
	u.mu.Lock()
	u.entries[subject] = time.Now().Add(DefaultRevocationTTL)
	u.mu.Unlock()
}

// Unblock removes a subject from the ban list.
func (u *UserBan) Unblock(subject string) {
	u.mu.Lock()
	delete(u.entries, subject)
	u.mu.Unlock()
}

// IsBanned reports whether a subject is banned.
func (u *UserBan) IsBanned(subject string) bool {
	u.mu.RLock()
	_, ok := u.entries[subject]
	u.mu.RUnlock()
	return ok
}

// List returns a snapshot of banned subjects.
func (u *UserBan) List() []string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	out := make([]string, 0, len(u.entries))
	for k := range u.entries {
		out = append(out, k)
	}
	return out
}

// cleanupLoop periodically removes expired entries to free memory.
func (u *UserBan) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-u.stop:
			return
		case <-ticker.C:
			u.sweep()
		}
	}
}

func (u *UserBan) sweep() {
	now := time.Now()
	u.mu.Lock()
	for jti, exp := range u.entries {
		if now.After(exp) {
			delete(u.entries, jti)
		}
	}
	u.mu.Unlock()
}
