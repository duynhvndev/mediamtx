// Package auth contains the authentication system.
package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/bluenviron/mediamtx/internal/conf"
	"github.com/bluenviron/mediamtx/internal/logger"
	"github.com/bluenviron/mediamtx/internal/protocols/httpp"
	"github.com/bluenviron/mediamtx/internal/protocols/tls"
)

const (
	maxInboundBodySize = 128 * 1024
	jwksRefreshPeriod  = 60 * 60 * time.Second
)

func isHTTP(req *Request) bool {
	return req.Protocol == ProtocolHLS || req.Protocol == ProtocolWebRTC ||
		req.Action == conf.AuthActionPlayback ||
		req.Action == conf.AuthActionAPI ||
		req.Action == conf.AuthActionMetrics ||
		req.Action == conf.AuthActionPprof
}

func matchesPermission(perms []conf.AuthInternalUserPermission, req *Request) bool {
	for _, perm := range perms {
		if perm.Action == req.Action {
			if perm.Action == conf.AuthActionPublish ||
				perm.Action == conf.AuthActionRead ||
				perm.Action == conf.AuthActionPlayback {
				switch {
				case perm.Path == "":
					return true

				case strings.HasPrefix(perm.Path, "~"):
					regexp, err := regexp.Compile(perm.Path[1:])
					if err == nil && regexp.MatchString(req.Path) {
						return true
					}

				case perm.Path == req.Path:
					return true
				}
			} else {
				return true
			}
		}
	}

	return false
}

func getToken(tokenInHTTPQuery bool, req *Request) string {
	switch {
	case req.Credentials.Token != "":
		return req.Credentials.Token

	case req.Credentials.Pass != "":
		return req.Credentials.Pass

		// always allow passing tokens through query parameters with RTSP and RTMP since there's no alternative.
	case req.Protocol == ProtocolRTSP || req.Protocol == ProtocolRTMP ||
		(tokenInHTTPQuery && isHTTP(req)):
		v, err := url.ParseQuery(req.Query)
		if err == nil {
			if len(v["token"]) == 1 {
				return v["token"][0]
			}

			// legacy query key
			if len(v["jwt"]) == 1 {
				return v["jwt"][0]
			}
		}
	}

	return ""
}

// Manager is the authentication manager.
type Manager struct {
	Method             conf.AuthMethod
	InternalUsers      []conf.AuthInternalUser
	HTTPAddress        string
	HTTPFingerprint    string
	HTTPExclude        []conf.AuthInternalUserPermission
	JWTJWKS            string
	JWTJWKSFingerprint string
	JWTClaimKey        string
	JWTExclude         []conf.AuthInternalUserPermission
	JWTInHTTPQuery     *bool
	JWTIssuer          string
	JWTAudience        string
	ReadTimeout        time.Duration
	Parent             logger.Writer

	wrapTransport   func(http.RoundTripper) http.RoundTripper
	mutex           sync.RWMutex
	jwksLastRefresh time.Time
	jwtKeyFunc      keyfunc.Keyfunc

	// [ARENA / JAVA] hybrid mode, see conf.AuthHTTPActions: with Method jwt,
	// these actions are authorized by HTTPAddress instead of the JWT.
	HTTPActions []conf.AuthAction
}

// Initialize initializes the manager.
func (m *Manager) Initialize() {
	m.wrapTransport = func(tr http.RoundTripper) http.RoundTripper {
		return &httpp.LoggerTransport{Transport: tr, Log: m.Parent}
	}
}

// ReloadInternalUsers reloads InternalUsers.
func (m *Manager) ReloadInternalUsers(u []conf.AuthInternalUser) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.InternalUsers = u
}

// Authenticate authenticates a request.
// The result carries the authenticated user (sub) and, when JWT-based, the token id (jti).
func (m *Manager) Authenticate(req *Request) (*Result, *Error) {
	var token string
	if m.Method == conf.AuthMethodHTTP || m.Method == conf.AuthMethodJWT {
		token = getToken(m.Method == conf.AuthMethodJWT && m.JWTInHTTPQuery != nil && *m.JWTInHTTPQuery, req)
	}

	var res *Result
	var err error

	switch m.Method {
	case conf.AuthMethodInternal:
		res, err = m.authenticateInternal(req)

	case conf.AuthMethodHTTP:
		res, err = m.authenticateHTTP(req, token)

	default:
		// [ARENA / JAVA] hybrid: selected actions (publish) go to the Java auth service.
		if slices.Contains(m.HTTPActions, req.Action) {
			res, err = m.authenticateHTTP(req, token)
		} else {
			res, err = m.authenticateJWT(req, token)
		}
	}

	if err != nil {
		return nil, &Error{
			Wrapped:        err,
			AskCredentials: req.EnableAskCredentials && req.Credentials.User == "" && req.Credentials.Pass == "" && token == "",
		}
	}

	return res, nil
}

func (m *Manager) authenticateInternal(req *Request) (*Result, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, u := range m.InternalUsers {
		if ok := m.authenticateWithUser(req, &u); ok {
			return &Result{User: req.Credentials.User}, nil
		}
	}

	return nil, fmt.Errorf("authentication failed")
}

func (m *Manager) authenticateWithUser(
	req *Request,
	u *conf.AuthInternalUser,
) bool {
	if len(u.IPs) != 0 && !u.IPs.Contains(req.IP) {
		return false
	}

	if !matchesPermission(u.Permissions, req) {
		return false
	}

	if u.User != "any" {
		if req.CustomVerifyFunc != nil {
			if ok := req.CustomVerifyFunc(string(u.User), string(u.Pass)); !ok {
				return false
			}
		} else {
			if !u.User.Check(req.Credentials.User) || !u.Pass.Check(req.Credentials.Pass) {
				return false
			}
		}
	}

	return true
}

func (m *Manager) authenticateHTTP(req *Request, token string) (*Result, error) {
	if matchesPermission(m.HTTPExclude, req) {
		return &Result{User: req.Credentials.User}, nil
	}

	// [ARENA / JAVA] Arena runs hybrid auth (authMethod: jwt + authHTTPActions:
	// [publish]): only PUBLISH reaches this call, once per publish connection
	// (RTMP, RTMPS, SRT). Reads, playback and the admin API are verified locally
	// with the JWT (JWKS) and never reach Java. For publish the Java service:
	//   1. Maps protocol + "encrypted" to rtmp / rtmps / srt / srts and checks it
	//      is allowed on this server.
	//   2. Verifies the publish ticket in "token" (RTMP: ?token= of the URL,
	//      SRT: password of the stream ID): HMAC bound to "path", not expired.
	//   3. Checks stream_key ownership: HMAC(sub, nonce, mode) matches (CPU).
	//   4. Checks the livestream is UPCOMING or ONGOING (not ENDED / FAILED) and
	//      the ticket's session is the latest join (or the live's Egress).
	//   5. Replies fast (timeout = readTimeout). If Java is down nobody can
	//      publish; viewers are not affected.
	// See livestream-arena/docs/designs/0001-live-auth-hybrid.md and 0008.
	// Requests matching authHTTPExclude never reach Java (keep it empty).
	enc, _ := json.Marshal(struct {
		IP        string     `json:"ip"`
		User      string     `json:"user"`
		Password  string     `json:"password"`
		Token     string     `json:"token"`
		Action    string     `json:"action"`
		Path      string     `json:"path"`
		Protocol  string     `json:"protocol"`
		ID        *uuid.UUID `json:"id"`
		Query     string     `json:"query"`
		UserAgent string     `json:"userAgent"`
		Encrypted bool       `json:"encrypted"` // Arena fork (design 0008)
	}{
		IP:        req.IP.String(),
		User:      req.Credentials.User,
		Password:  req.Credentials.Pass,
		Token:     token,
		Action:    string(req.Action),
		Path:      req.Path,
		Protocol:  string(req.Protocol),
		ID:        req.ID,
		Query:     req.Query,
		UserAgent: req.UserAgent,
		Encrypted: req.Encrypted,
	})

	tr := &http.Transport{
		TLSClientConfig: tls.MakeConfig(m.HTTPFingerprint),
	}
	defer tr.CloseIdleConnections()

	httpClient := &http.Client{
		Timeout:   m.ReadTimeout,
		Transport: m.wrapTransport(tr),
	}

	httpRes, err := httpClient.Post(m.HTTPAddress, "application/json", bytes.NewReader(enc))
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer httpRes.Body.Close()

	if httpRes.StatusCode < 200 || httpRes.StatusCode > 299 {
		resBody, err2 := io.ReadAll(&customLimitReader{httpRes.Body, maxInboundBodySize})
		if err2 == nil && len(resBody) != 0 {
			return nil, fmt.Errorf("server replied with code %d: %s", httpRes.StatusCode, string(resBody))
		}

		return nil, fmt.Errorf("server replied with code %d", httpRes.StatusCode)
	}

	resBody, err := io.ReadAll(&customLimitReader{httpRes.Body, maxInboundBodySize})
	if err != nil {
		return nil, fmt.Errorf("invalid HTTP response: %w", err)
	}

	var expireAt *time.Time
	user := req.Credentials.User
	var jti string
	var srtPassphrase string

	// [ARENA / JAVA] Response body of the Java auth service (all fields optional):
	//
	//   200 {"user": "<ticket sub>", "jti": "<ticket jti>", "srt_passphrase": "<p>"}
	//
	// - user, jti: identity of the ticket. Stored on the connection, shown as
	//   "user"/"jti" in /v3/rtmpconns and /v3/srtconns and passed to hooks as
	//   MTX_USER/MTX_JTI (Kafka STREAM_START).
	// - srt_passphrase (srts only): passphrase of this SRT session; replaces the
	//   path's srtPublishPassphrase.
	//   Omit them and mediamtx falls back to the basic-auth user and empty jti.
	// - expireAt (optional): mediamtx closes the connection at this time. Arena
	//   does NOT send it for publish, so a live is never cut when the token
	//   expires; Java ends lives by kicking + marking them ENDED.
	//
	// A malformed body is ignored and the request is still allowed: Java must
	// answer with a non-2xx status (401/403) to deny.
	if len(bytes.TrimSpace(resBody)) != 0 {
		var out struct {
			ExpireAt *time.Time `json:"expireAt"`
			User     string     `json:"user"` // Arena fork
			JTI      string     `json:"jti"`  // Arena fork
			// Arena fork (design 0008): passphrase of an encrypted SRT publish.
			SRTPassphrase string `json:"srt_passphrase"`
		}

		err = json.Unmarshal(resBody, &out)
		if err == nil {
			if out.ExpireAt != nil && !time.Now().Before(*out.ExpireAt) {
				return nil, fmt.Errorf("HTTP authentication expired")
			}
			expireAt = out.ExpireAt
			if out.User != "" {
				user = out.User
			}
			jti = out.JTI
			srtPassphrase = out.SRTPassphrase
		}
	}

	return &Result{User: user, JTI: jti, ExpiresAt: expireAt, SRTPassphrase: srtPassphrase}, nil
}

func (m *Manager) authenticateJWT(req *Request, token string) (*Result, error) {
	if matchesPermission(m.JWTExclude, req) {
		return &Result{User: req.Credentials.User}, nil
	}

	if token == "" {
		return nil, fmt.Errorf("JWT not provided")
	}

	keyfunc, err := m.pullJWTJWKS()
	if err != nil {
		return nil, err
	}

	var opts []jwt.ParserOption
	if m.JWTIssuer != "" {
		opts = append(opts, jwt.WithIssuer(m.JWTIssuer))
	}
	if m.JWTAudience != "" {
		opts = append(opts, jwt.WithAudience(m.JWTAudience))
	}

	var cc jwtClaims
	cc.permissionsKey = m.JWTClaimKey
	_, err = jwt.ParseWithClaims(token, &cc, keyfunc, opts...)
	if err != nil {
		return nil, err
	}

	if !matchesPermission(cc.permissions, req) {
		return nil, fmt.Errorf("user doesn't have permission to perform action")
	}

	res := &Result{User: cc.Subject, JTI: cc.ID}
	if cc.ExpiresAt != nil {
		res.ExpiresAt = &cc.ExpiresAt.Time
	}

	return res, nil
}

func (m *Manager) pullJWTJWKS() (jwt.Keyfunc, error) {
	now := time.Now()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if now.Sub(m.jwksLastRefresh) >= jwksRefreshPeriod {
		tr := &http.Transport{
			TLSClientConfig: tls.MakeConfig(m.JWTJWKSFingerprint),
		}
		defer tr.CloseIdleConnections()

		httpClient := &http.Client{
			Timeout:   m.ReadTimeout,
			Transport: m.wrapTransport(tr),
		}

		res, err := httpClient.Get(m.JWTJWKS)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		if res.StatusCode < 200 || res.StatusCode > 299 {
			return nil, fmt.Errorf("JWKS server replied with code %d", res.StatusCode)
		}

		var raw json.RawMessage
		err = json.NewDecoder(&customLimitReader{res.Body, maxInboundBodySize}).Decode(&raw)
		if err != nil {
			return nil, err
		}

		tmp, err := keyfunc.NewJWKSetJSON(raw)
		if err != nil {
			return nil, err
		}

		m.jwtKeyFunc = tmp
		m.jwksLastRefresh = now
	}

	return m.jwtKeyFunc.Keyfunc, nil
}

// RefreshJWTJWKS refreshes the JWT JWKS.
func (m *Manager) RefreshJWTJWKS() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.jwksLastRefresh = time.Time{}
}
