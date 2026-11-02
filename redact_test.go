package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDumpRequestRedactsCredentialHeadersAndPreservesRequest(t *testing.T) {
	const body = `{"name":"example","payload":"0123456789"}`
	var gotAuth, gotKey, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotKey = r.Header.Get("X-Api-Key")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
	}))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "NIRMATA-API secret-auth-value")
	req.Header.Set("x-api-key", "secret-key-value")
	req.Header.Set("Cookie", "session=secret-cookie-value")

	dump := dumpRequest(req)
	for _, secret := range []string{"secret-auth-value", "secret-key-value", "secret-cookie-value"} {
		if strings.Contains(dump, secret) {
			t.Errorf("dump contains %q:\n%s", secret, dump)
		}
	}
	if !strings.Contains(dump, "[REDACTED]") {
		t.Errorf("dump missing [REDACTED]:\n%s", dump)
	}
	if !strings.Contains(dump, body) {
		t.Errorf("dump missing body:\n%s", dump)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if gotAuth != "NIRMATA-API secret-auth-value" {
		t.Errorf("server got Authorization %q", gotAuth)
	}
	if gotKey != "secret-key-value" {
		t.Errorf("server got X-Api-Key %q", gotKey)
	}
	if gotBody != body {
		t.Errorf("server got body %q, want %q", gotBody, body)
	}
}

func makeTestJWT(exp time.Time) string {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := enc.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp.Unix())))
	return header + "." + payload + ".sig"
}

func TestServiceAccountTokenAuthConcurrentSetAuthHeader(t *testing.T) {
	token := makeTestJWT(time.Now().Add(time.Hour))
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": token}) //nolint:errcheck
	}))
	defer srv.Close()

	auth := NewServiceAccountTokenAuth("sa-token", srv.URL, "client", false)

	const n = 50
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, "http://example.invalid", nil)
			if err := auth.SetAuthHeader(req); err != nil {
				errs <- err.Error()
				return
			}
			// A second call on the same request must not duplicate the header.
			if err := auth.SetAuthHeader(req); err != nil {
				errs <- err.Error()
				return
			}
			if v := req.Header.Values("Authorization"); len(v) != 1 || v[0] != "Bearer "+token {
				errs <- fmt.Sprintf("unexpected Authorization values: %v", v)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if c := atomic.LoadInt32(&calls); c != 1 {
		t.Errorf("token exchange called %d times, want 1", c)
	}
}

func TestStaticAuthProvidersSetSingleHeader(t *testing.T) {
	for _, p := range []AuthProvider{NewAPITokenAuth("k"), NewJWTTokenAuth("j")} {
		req, _ := http.NewRequest(http.MethodGet, "http://example.invalid", nil)
		p.SetAuthHeader(req) //nolint:errcheck
		p.SetAuthHeader(req) //nolint:errcheck
		if v := req.Header.Values("Authorization"); len(v) != 1 {
			t.Errorf("%T: got %d Authorization headers", p, len(v))
		}
	}
}
