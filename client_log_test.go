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

func errorServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid_client","client_secret":"echo-should-not-leak"}`) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestNon2xxBodyAbsentFromErrorMessage verifies that the raw HTTP response body
// is not embedded in Error.Message for non-2xx responses, regardless of verbosity.
func TestNon2xxBodyAbsentFromErrorMessage(t *testing.T) {
	srv := errorServer(t)
	c := NewClientWithAPIKey(srv.URL, "test-api-key", false)

	t.Run("get path", func(t *testing.T) {
		_, _, err := c.GetURL(ServiceUsers, "test/path")
		if err == nil {
			t.Fatal("expected error for 401 response, got nil")
		}
		if strings.Contains(err.Message(), "echo-should-not-leak") {
			t.Errorf("Error.Message contains response body: %s", err.Message())
		}
		if !strings.Contains(err.Message(), "401") {
			t.Errorf("Error.Message should contain status code, got: %s", err.Message())
		}
	})

	t.Run("send path", func(t *testing.T) {
		_, err := c.PostFromJSON(ServiceUsers, "test/path", map[string]interface{}{}, nil)
		if err == nil {
			t.Fatal("expected error for 401 response, got nil")
		}
		if strings.Contains(err.Message(), "echo-should-not-leak") {
			t.Errorf("Error.Message contains response body: %s", err.Message())
		}
	})
}

// TestNon2xxBodyLogVisibility verifies that non-2xx response bodies are absent
// from logs below V=5 and present at V=5.
func TestNon2xxBodyLogVisibility(t *testing.T) {
	tests := []struct {
		verbosity   int
		wantBody    bool
		checkStatus bool // V=3 additionally verifies the response-status log line is present
	}{
		{3, false, true},
		{4, false, false},
		{5, true, false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(fmt.Sprintf("V%d", tc.verbosity), func(t *testing.T) {
			srv := errorServer(t)
			buf := captureKlogAtVerbosity(t, tc.verbosity)

			c := NewClientWithAPIKey(srv.URL, "test-api-key", false)
			c.GetURL(ServiceUsers, "test/path") //nolint:errcheck

			logged := buf.String()
			if tc.wantBody && !strings.Contains(logged, "echo-should-not-leak") {
				t.Errorf("response body should appear in V=%d logs, absent:\n%s", tc.verbosity, logged)
			}
			if !tc.wantBody && strings.Contains(logged, "echo-should-not-leak") {
				t.Errorf("response body found in V=%d logs:\n%s", tc.verbosity, logged)
			}
			if tc.checkStatus && !strings.Contains(logged, "HTTP response status=") {
				t.Errorf("expected HTTP response status log at V=%d, got:\n%s", tc.verbosity, logged)
			}
		})
	}
}
