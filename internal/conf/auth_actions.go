package conf

import (
	"encoding/json"
	"strings"

	"github.com/bluenviron/mediamtx/internal/conf/jsonwrapper"
)

// AuthActions is a list of authentication actions.
// [ARENA / JAVA] fork type, used by authHTTPActions (hybrid auth).
type AuthActions []AuthAction

// UnmarshalEnv implements env.Unmarshaler (e.g. MTX_AUTHHTTPACTIONS=publish,read).
func (d *AuthActions) UnmarshalEnv(_ string, v string) error {
	if v == "" {
		*d = AuthActions{}
		return nil
	}

	byts, _ := json.Marshal(strings.Split(v, ","))
	return jsonwrapper.Unmarshal(byts, d)
}
