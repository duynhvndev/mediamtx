package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type userBanReq struct {
	Subject string `json:"subject"`
}

func (a *API) onUserBanAdd(ctx *gin.Context) {
	var body userBanReq
	if err := ctx.ShouldBindJSON(&body); err != nil || body.Subject == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest,
			gin.H{"error": "missing or invalid 'subject'"})
		return
	}

	a.AuthManager.UserBanBlock(body.Subject)

	// kick active RTMP sessions of this user
	kicked := a.kickUserSessions(body.Subject)

	ctx.JSON(http.StatusOK, gin.H{
		"subject":        body.Subject,
		"kickedSessions": kicked,
	})
}

func (a *API) onUserBanDelete(ctx *gin.Context) {
	subject := ctx.Param("subject")
	if subject == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest,
			gin.H{"error": "missing 'subject'"})
		return
	}
	a.AuthManager.UserBanUnblock(subject)
	ctx.Status(http.StatusOK)
}

func (a *API) onUserBanList(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{"items": a.AuthManager.UserBanList()})
}

// kickUserSessions terminates active RTMP and HLS sessions belonging to the subject.
func (a *API) kickUserSessions(subject string) int {
	kicked := 0

	// Kick RTMP connections
	if !interfaceIsEmpty(a.RTMPServer) {
		if data, err := a.RTMPServer.APIConnsList(); err == nil {
			for _, conn := range data.Items {
				if conn.User == subject {
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
				if conn.User == subject {
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
				if sess.User == subject {
					_ = a.HLSServer.APISessionsKick(sess.ID)
					kicked++
				}
			}
		}
	}

	return kicked
}
