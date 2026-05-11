package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type revokeReq struct {
	JTI string `json:"jti"`
}

func (a *API) onAuthRevokeAdd(ctx *gin.Context) {
	var body revokeReq
	if err := ctx.ShouldBindJSON(&body); err != nil || body.JTI == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest,
			gin.H{"error": "missing or invalid 'jti'"})
		return
	}
	a.AuthManager.RevocationBlock(body.JTI)

	// kick active RTMP + HLS sessions whose token had this jti
	kicked := a.kickJTISessions(body.JTI)

	ctx.JSON(http.StatusOK, gin.H{
		"jti":            body.JTI,
		"kickedSessions": kicked,
	})
}

// kickJTISessions terminates active RTMP and HLS sessions belonging to the jti.
func (a *API) kickJTISessions(jti string) int {
	kicked := 0

	// Kick RTMP connections
	if !interfaceIsEmpty(a.RTMPServer) {
		if data, err := a.RTMPServer.APIConnsList(); err == nil {
			for _, conn := range data.Items {
				if conn.JTI == jti {
					_ = a.RTMPServer.APIConnsKick(conn.ID)
					kicked++
				}
			}
		}
	}

	// Kick RTMPS connections
	if !interfaceIsEmpty(a.RTMPSServer) {
		if data, err := a.RTMPSServer.APIConnsList(); err == nil {
			for _, conn := range data.Items {
				if conn.JTI == jti {
					_ = a.RTMPSServer.APIConnsKick(conn.ID)
					kicked++
				}
			}
		}
	}

	// Kick HLS sessions
	if !interfaceIsEmpty(a.HLSServer) {
		if data, err := a.HLSServer.APISessionsList(); err == nil {
			for _, sess := range data.Items {
				if sess.JTI == jti {
					_ = a.HLSServer.APISessionsKick(sess.ID)
					kicked++
				}
			}
		}
	}

	return kicked
}

func (a *API) onAuthRevokeDelete(ctx *gin.Context) {
	jti := ctx.Param("jti")
	if jti == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest,
			gin.H{"error": "missing 'jti'"})
		return
	}
	a.AuthManager.RevocationUnblock(jti)
	ctx.Status(http.StatusOK)
}

func (a *API) onAuthRevokeList(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{"items": a.AuthManager.RevocationList()})
}
