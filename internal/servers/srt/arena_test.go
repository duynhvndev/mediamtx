package srt

import (
	"bufio"
	"fmt"
	"testing"
	"time"

	"github.com/bluenviron/mediacommon/v2/pkg/formats/mpegts"
	tscodecs "github.com/bluenviron/mediacommon/v2/pkg/formats/mpegts/codecs"
	srt "github.com/datarhei/gosrt"
	"github.com/stretchr/testify/require"

	"github.com/bluenviron/mediamtx/internal/auth"
	"github.com/bluenviron/mediamtx/internal/conf"
	"github.com/bluenviron/mediamtx/internal/defs"
	"github.com/bluenviron/mediamtx/internal/test"
)

// Arena fork (design 0008): the Java auth service decides srt vs srts and
// returns a passphrase per publish session.

const arenaSessionPassphrase = "session-passphrase-0123456789"

func arenaServer(t *testing.T, pm *test.PathManager) *Server {
	s := &Server{
		Address:           "127.0.0.1:8890",
		ReadTimeout:       conf.Duration(10 * time.Second),
		WriteTimeout:      conf.Duration(10 * time.Second),
		UDPMaxPayloadSize: 1472,
		PathManager:       pm,
		Parent:            test.NilLogger,
	}
	err := s.Initialize()
	require.NoError(t, err)
	return s
}

func arenaDial(t *testing.T, passphrase string) (srt.Conn, error) {
	srtConf := srt.DefaultConfig()
	address, err := srtConf.UnmarshalURL(
		"srt://127.0.0.1:8890?streamid=publish:teststream:arena:ticket")
	require.NoError(t, err)
	if passphrase != "" {
		srtConf.Passphrase = passphrase
	}
	require.NoError(t, srtConf.Validate())
	return srt.Dial("srt", address, srtConf)
}

func TestArenaPublishPassphrase(t *testing.T) {
	for _, ca := range []struct {
		name          string
		authPass      string
		pathPass      string
		clientPass    string
		wantEncrypted bool
		ok            bool
	}{
		{name: "srts, session passphrase", authPass: arenaSessionPassphrase,
			clientPass: arenaSessionPassphrase, wantEncrypted: true, ok: true},
		{name: "srts, wrong passphrase", authPass: arenaSessionPassphrase,
			clientPass: "another-passphrase-000", wantEncrypted: true, ok: false},
		{name: "srts required, client not encrypted", authPass: arenaSessionPassphrase,
			ok: false},
		{name: "srt, not encrypted", ok: true},
		{name: "srt only, client encrypted", clientPass: arenaSessionPassphrase,
			wantEncrypted: true, ok: false},
		{name: "path passphrase when auth returns none", pathPass: arenaSessionPassphrase,
			clientPass: arenaSessionPassphrase, wantEncrypted: true, ok: true},
	} {
		t.Run(ca.name, func(t *testing.T) {
			encrypted := make(chan bool, 1)
			s := arenaServer(t, &test.PathManager{
				FindPathConfImpl: func(req defs.PathFindPathConfReq) (*defs.PathFindPathConfRes, error) {
					require.Equal(t, auth.ProtocolSRT, req.AccessRequest.Proto)
					require.Equal(t, "ticket", req.AccessRequest.Credentials.Pass)
					encrypted <- req.AccessRequest.Encrypted
					return &defs.PathFindPathConfRes{
						Conf:    &conf.Path{SRTPublishPassphrase: ca.pathPass},
						AuthRes: &auth.Result{User: "sub", JTI: "jti", SRTPassphrase: ca.authPass},
					}, nil
				},
				AddPublisherImpl: func(_ defs.PathAddPublisherReq) (*defs.PathAddPublisherRes, error) {
					return nil, fmt.Errorf("not needed")
				},
			})
			defer s.Close()

			conn, err := arenaDial(t, ca.clientPass)
			if conn != nil {
				defer conn.Close()
			}
			require.Equal(t, ca.wantEncrypted, <-encrypted)
			if ca.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestArenaPublishIdentity(t *testing.T) {
	added := make(chan defs.PathAddPublisherReq, 1)
	s := arenaServer(t, &test.PathManager{
		FindPathConfImpl: func(_ defs.PathFindPathConfReq) (*defs.PathFindPathConfRes, error) {
			return &defs.PathFindPathConfRes{
				Conf: &conf.Path{},
				AuthRes: &auth.Result{
					User: "sub-1", JTI: "jti-1", SRTPassphrase: arenaSessionPassphrase,
				},
			}, nil
		},
		AddPublisherImpl: func(req defs.PathAddPublisherReq) (*defs.PathAddPublisherRes, error) {
			added <- req
			return nil, fmt.Errorf("stop here")
		},
	})
	defer s.Close()

	conn, err := arenaDial(t, arenaSessionPassphrase)
	require.NoError(t, err)
	defer conn.Close()

	list, err := s.APIConnsList()
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	require.Equal(t, "sub-1", list.Items[0].User)
	require.Equal(t, "jti-1", list.Items[0].JTI)

	track := &mpegts.Track{Codec: &tscodecs.H264{}}
	bw := bufio.NewWriter(conn)
	w := &mpegts.Writer{W: bw, Tracks: []*mpegts.Track{track}}
	require.NoError(t, w.Initialize())
	// the MPEG-TS muxer needs two PES packets in order to write the first one
	require.NoError(t, w.WriteH264(track, 0, 0, [][]byte{
		test.FormatH264.SPS, test.FormatH264.PPS, {5, 1},
	}))
	require.NoError(t, w.WriteH264(track, 0, 0, [][]byte{{5, 2}}))
	require.NoError(t, bw.Flush())

	req := <-added
	require.True(t, req.AccessRequest.SkipAuth)
	require.Equal(t, "sub-1", req.User)
	require.Equal(t, "jti-1", req.JTI)
}
