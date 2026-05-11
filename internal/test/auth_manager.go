// Package test contains test utilities.
package test

import "github.com/bluenviron/mediamtx/internal/auth"

// AuthManager is a dummy auth manager.
type AuthManager struct {
	AuthenticateImpl   func(req *auth.Request) (string, string, *auth.Error)
	RefreshJWTJWKSImpl func()
}

// Authenticate replicates auth.Manager.Authenticate.
func (m *AuthManager) Authenticate(req *auth.Request) (string, string, *auth.Error) {
	return m.AuthenticateImpl(req)
}

// RefreshJWTJWKS is a function that simulates a JWKS refresh.
func (m *AuthManager) RefreshJWTJWKS() {
	m.RefreshJWTJWKSImpl()
}

// RevocationBlock is a stub.
func (m *AuthManager) RevocationBlock(_ string) {}

// RevocationUnblock is a stub.
func (m *AuthManager) RevocationUnblock(_ string) {}

// RevocationList is a stub.
func (m *AuthManager) RevocationList() []string { return nil }

// UserBanBlock is a stub.
func (m *AuthManager) UserBanBlock(_ string) {}

// UserBanUnblock is a stub.
func (m *AuthManager) UserBanUnblock(_ string) {}

// UserBanList is a stub.
func (m *AuthManager) UserBanList() []string { return nil }

// NilAuthManager is an auth manager that accepts everything.
var NilAuthManager = &AuthManager{
	AuthenticateImpl: func(_ *auth.Request) (string, string, *auth.Error) {
		return "", "", nil
	},
}
