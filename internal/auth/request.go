package auth

import (
	"net"

	"github.com/google/uuid"

	"github.com/bluenviron/mediamtx/internal/conf"
)

// Protocol is a protocol.
type Protocol string

// protocols.
const (
	ProtocolRTSP   Protocol = "rtsp"
	ProtocolRTMP   Protocol = "rtmp"
	ProtocolHLS    Protocol = "hls"
	ProtocolWebRTC Protocol = "webrtc"
	ProtocolSRT    Protocol = "srt"
	ProtocolMoQ    Protocol = "moq"
)

// Request is an authentication request.
type Request struct {
	Action      conf.AuthAction
	Path        string // only for ActionPublish, ActionRead, ActionPlayback
	Query       string
	Protocol    Protocol   // only for ActionPublish, ActionRead
	ID          *uuid.UUID // only for ActionPublish, ActionRead
	UserAgent   string
	Credentials *Credentials
	IP          net.IP
	// [ARENA / JAVA] Transport is encrypted: RTMP on the RTMPS listener, SRT with a
	// passphrase. Sent to the Java auth service as "encrypted" so it can tell
	// rtmp / rtmps / srt / srts apart (design 0008).
	Encrypted            bool
	CustomVerifyFunc     func(expectedUser string, expectedPass string) bool
	EnableAskCredentials bool
}
