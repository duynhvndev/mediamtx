package auth

import "time"

// Result is the result of Authenticate().
type Result struct {
	User      string
	ExpiresAt *time.Time

	// [ARENA / JAVA] JWT ID. With authMethod: http it is the "jti" field of the
	// Java auth response; with authMethod: jwt it is the token's jti claim.
	JTI string

	// [ARENA / JAVA] SRT passphrase of this publish session ("srt_passphrase" of
	// the Java auth response, design 0008). Empty = use the path's
	// srtPublishPassphrase.
	SRTPassphrase string
}
