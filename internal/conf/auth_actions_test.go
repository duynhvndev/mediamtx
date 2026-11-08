package conf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Arena fork: authHTTPActions must be settable from the environment (k8s).
func TestAuthActionsUnmarshalEnv(t *testing.T) {
	for _, ca := range []struct {
		name string
		env  string
		out  AuthActions
		err  string
	}{
		{name: "empty", env: "", out: AuthActions{}},
		{name: "single", env: "publish", out: AuthActions{AuthActionPublish}},
		{name: "multiple", env: "publish,read", out: AuthActions{AuthActionPublish, AuthActionRead}},
		{name: "invalid", env: "pubish", err: "invalid auth action: 'pubish'"},
	} {
		t.Run(ca.name, func(t *testing.T) {
			var d AuthActions
			err := d.UnmarshalEnv("", ca.env)
			if ca.err != "" {
				require.EqualError(t, err, ca.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, ca.out, d)
		})
	}
}
