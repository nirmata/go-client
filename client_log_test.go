package client

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"k8s.io/klog/v2"
)

// captureKlogAtVerbosity redirects klog output to a buffer at the given verbosity
// level. klog writes to os.Stderr by default (logtostderr=true); both the output
// destination and the logtostderr flag must be changed together to capture V-level
// logs in tests.
func captureKlogAtVerbosity(t *testing.T, verbosity int) *strings.Builder {
	t.Helper()
	sb := &strings.Builder{}
	fs := flag.NewFlagSet("test-klog", flag.ContinueOnError)
	klog.InitFlags(fs)
	fs.Set("logtostderr", "false")            //nolint:errcheck
	fs.Set("v", fmt.Sprintf("%d", verbosity)) //nolint:errcheck
	klog.SetOutput(sb)
	t.Cleanup(func() {
		klog.SetOutput(os.Stderr)
		fs.Set("logtostderr", "true") //nolint:errcheck
		fs.Set("v", "0")              //nolint:errcheck
	})
	return sb
}

func credentialServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"id":           "test-id-123",
			"modelIndex":   "test",
			"access_token": "eyJfakeResponseJWT.payload.signature",
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestLogsAtV3DoNotContainSensitiveData(t *testing.T) {
	srv := credentialServer(t)
	buf := captureKlogAtVerbosity(t, 3)

	c := NewClientWithAPIKey(srv.URL, "super-secret-api-key-v3test", false)
	c.PostFromJSON(ServiceUsers, "test", map[string]interface{}{ //nolint:errcheck
		"grant_type":    "client_credentials",
		"client_id":     "test-client",
		"client_secret": "should-not-appear-in-logs",
	}, nil)

	logged := buf.String()

	if strings.Contains(logged, "super-secret-api-key-v3test") {
		t.Errorf("API key found in V=3 logs:\n%s", logged)
	}
	if strings.Contains(logged, "should-not-appear-in-logs") {
		t.Errorf("client_secret found in V=3 logs:\n%s", logged)
	}
	if strings.Contains(logged, "eyJfakeResponseJWT") {
		t.Errorf("JWT response token found in V=3 logs:\n%s", logged)
	}
	if !strings.Contains(logged, "HTTP") {
		t.Errorf("expected HTTP method/URL log line at V=3, got nothing:\n%s", logged)
	}
}

func TestLogsAtV5ContainFullRequestDump(t *testing.T) {
	srv := credentialServer(t)
	buf := captureKlogAtVerbosity(t, 5)

	c := NewClientWithAPIKey(srv.URL, "super-secret-api-key-v5test", false)
	c.PostFromJSON(ServiceUsers, "test", map[string]interface{}{ //nolint:errcheck
		"client_secret": "should-appear-at-v5",
	}, nil)

	logged := buf.String()

	if !strings.Contains(logged, "should-appear-at-v5") {
		t.Errorf("expected request body in V=5 logs for debugging, absent:\n%s", logged)
	}
	if !strings.Contains(logged, "eyJfakeResponseJWT") {
		t.Errorf("expected response JWT in V=5 logs for debugging, absent:\n%s", logged)
	}
}
