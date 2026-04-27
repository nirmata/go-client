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

	// Test get() path (GetURL → get)
	_, _, getErr := c.GetURL(ServiceUsers, "test/path")
	if getErr == nil {
		t.Fatal("expected error for 401 response from GetURL, got nil")
	}
	if strings.Contains(getErr.Message(), "echo-should-not-leak") {
		t.Errorf("get() path: Error.Message contains response body: %s", getErr.Message())
	}
	if !strings.Contains(getErr.Message(), "401") {
		t.Errorf("get() path: Error.Message should contain status code, got: %s", getErr.Message())
	}

	// Test send() path (PostFromJSON → send) — the auth/token exchange path
	_, sendErr := c.PostFromJSON(ServiceUsers, "test/path", map[string]interface{}{}, nil)
	if sendErr == nil {
		t.Fatal("expected error for 401 response from PostFromJSON, got nil")
	}
	if strings.Contains(sendErr.Message(), "echo-should-not-leak") {
		t.Errorf("send() path: Error.Message contains response body: %s", sendErr.Message())
	}
}

// TestNon2xxBodyAbsentFromLogsAtV3 verifies that the response body from a
// non-2xx response does not appear in klog output at V=3 or below.
// At V=3, the old V(1) log would have included the body — this test catches
// any regression of that pattern.
func TestNon2xxBodyAbsentFromLogsAtV3(t *testing.T) {
	srv := errorServer(t)
	buf := captureKlogAtVerbosity(t, 3)

	c := NewClientWithAPIKey(srv.URL, "test-api-key", false)
	c.GetURL(ServiceUsers, "test/path") //nolint:errcheck

	logged := buf.String()
	if strings.Contains(logged, "echo-should-not-leak") {
		t.Errorf("response body found in V=3 logs:\n%s", logged)
	}
	if !strings.Contains(logged, "HTTP response status=") {
		t.Errorf("expected HTTP response status log at V=3, got:\n%s", logged)
	}
}

// TestNon2xxBodyAbsentAtV4 verifies the response body is NOT present at V=4.
// Pre-fix: V(1) body log fires at V=4 → FAIL.
// Post-fix: V(1) log removed, V(5) log doesn't fire at V=4 → PASS.
// This test combined with TestNon2xxBodyPresentAtV5 confirms the body moves
// from V(1) to V(5), not that it simply disappears.
func TestNon2xxBodyAbsentAtV4(t *testing.T) {
	srv := errorServer(t)
	buf := captureKlogAtVerbosity(t, 4)

	c := NewClientWithAPIKey(srv.URL, "test-api-key", false)
	c.GetURL(ServiceUsers, "test/path") //nolint:errcheck

	logged := buf.String()
	if strings.Contains(logged, "echo-should-not-leak") {
		t.Errorf("response body found in V=4 logs:\n%s", logged)
	}
}

// TestNon2xxBodyPresentAtV5 verifies the response body IS present at V=5,
// so operators can diagnose non-2xx errors with -v=5.
func TestNon2xxBodyPresentAtV5(t *testing.T) {
	srv := errorServer(t)
	buf := captureKlogAtVerbosity(t, 5)

	c := NewClientWithAPIKey(srv.URL, "test-api-key", false)
	c.GetURL(ServiceUsers, "test/path") //nolint:errcheck

	logged := buf.String()
	if !strings.Contains(logged, "echo-should-not-leak") {
		t.Errorf("response body should appear in V=5 logs for debugging, absent:\n%s", logged)
	}
}
