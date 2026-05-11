package auth

import "time"

// Result is the result of Authenticate().
type Result struct {
	User      string
	JTI       string // JWT ID, set only for JWT authentication
	ExpiresAt *time.Time
}
