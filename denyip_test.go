package denyip_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/notsureifkevin/denyip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDenyIP(t *testing.T) {
	testCases := []struct {
		desc          string
		denyList      []string
		expectedError bool
	}{
		{
			desc:          "invalid ip",
			denyList:      []string{"foo"},
			expectedError: true,
		},
		{
			desc:          "no ip",
			denyList:      []string{},
			expectedError: true,
		},
		{
			desc:     "valid ip range",
			denyList: []string{"192.168.100.0/24"},
		},
		{
			desc:     "valid ip",
			denyList: []string{"10.10.10.10"},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			cfg := denyip.CreateConfig()
			cfg.IPDenyList = test.denyList

			ctx := context.Background()
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

			handler, err := denyip.New(ctx, next, cfg, "denyip-plugin")

			if test.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, handler)
			}
		})
	}
}

func TestNewDenyIP_ServeHTTP(t *testing.T) {
	testCases := []struct {
		desc       string
		denyList   []string
		remoteAddr string
		xff        string
		expected   int
	}{
		{
			desc:       "allowed ip with x-forwarded-for and remote address",
			denyList:   []string{"192.168.100.0/24"},
			remoteAddr: "20.20.20.21",
			xff:        "127.0.0.1, 172.16.100.22, 20.20.20.21",
			expected:   200,
		},
		{
			desc:       "allowed ip with x-forwarded-for",
			denyList:   []string{"192.168.100.0/24"},
			remoteAddr: "",
			xff:        "127.0.0.1, 20.20.20.20",
			expected:   200,
		},
		{
			desc:       "allowed ip with remote address",
			denyList:   []string{"20.20.20.21"},
			remoteAddr: "20.20.20.20:1234",
			xff:        "",
			expected:   200,
		},
		{
			desc:       "allowed ip range with remote address",
			denyList:   []string{"192.168.100.0/24"},
			remoteAddr: "20.20.20.20:1234",
			xff:        "",
			expected:   200,
		},
		{
			desc:       "denied ip with x-forwarded-for and remote address",
			denyList:   []string{"192.168.100.0/24"},
			remoteAddr: "192.168.100.15",
			xff:        "127.0.0.1, 172.16.100.25, 192.16.100.15",
			expected:   403,
		},
		{
			desc:       "denied ip with x-forwarded-for",
			denyList:   []string{"192.168.100.0/24"},
			remoteAddr: "",
			xff:        "127.0.0.1, 192.168.100.25",
			expected:   403,
		},
		{
			desc:       "denied ip with remote address",
			denyList:   []string{"20.20.20.21"},
			remoteAddr: "20.20.20.21:1234",
			xff:        "",
			expected:   403,
		},
		{
			desc:       "denied ip range with remote address",
			denyList:   []string{"192.168.100.0/24"},
			remoteAddr: "192.168.100.25:1234",
			xff:        "",
			expected:   403,
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
			recorder := httptest.NewRecorder()

			cfg := denyip.CreateConfig()
			cfg.IPDenyList = test.denyList

			ctx := context.Background()
			handler, err := denyip.New(ctx, next, cfg, "denyip-plugin")
			require.NoError(t, err)

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://10.10.10.10", nil)
			require.NoError(t, err)

			if test.remoteAddr != "" {
				req.RemoteAddr = test.remoteAddr
			}

			if test.xff != "" {
				req.Header.Add("X-Forwarded-For", test.xff)
			}

			handler.ServeHTTP(recorder, req)

			assert.Equal(t, test.expected, recorder.Code)
		})
	}
}
