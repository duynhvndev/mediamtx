package auth

import "time"

// Result is the result of Authenticate().
type Result struct {
	User      string
	ExpiresAt *time.Time

	// [ARENA / JAVA] JWT ID. With authMethod: http it is the "jti" field of the
	// Java auth response; with authMethod: jwt it is the token's jti claim.
	JTI string
}
