package client

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"testing"
	"time"
)

type optionsRoundTripper func(*http.Request) (*http.Response, error)

func (f optionsRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func optionsResponse(r *http.Request) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Request: r}
}

func TestClientOptionsPreserveHTTPSettings(t *testing.T) {
	base := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Proxy: http.ProxyFromEnvironment}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	redirectErr := fmt.Errorf("caller redirect policy")
	caller := &http.Client{Transport: base, Timeout: 7 * time.Second, Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return redirectErr }}
	var seenBase http.RoundTripper
	requests := 0
	c, err := NewClientWithOptions("https://one.example", NewAPITokenAuth("one"), ClientOptions{
		HTTPClient: caller,
		WrapTransport: func(rt http.RoundTripper) http.RoundTripper {
			seenBase = rt
			return optionsRoundTripper(func(r *http.Request) (*http.Response, error) {
				requests++
				if r.Header.Get("Authorization") != "NIRMATA-API one" {
					t.Errorf("legacy auth header lost: %q", r.Header.Get("Authorization"))
				}
				return optionsResponse(r), nil
			})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	actual := c.(*client).httpClient
	if actual == caller || seenBase != base || actual.Jar != jar || actual.Timeout != caller.Timeout {
		t.Fatal("HTTP client was not copied with settings/base preserved")
	}
	if actual.CheckRedirect(nil, nil) != redirectErr || caller.Transport != base || base.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("caller redirect/TLS settings changed")
	}
	if _, _, err := c.GetURL(ServiceLLMApps, "chat"); err != nil {
		t.Fatal(err)
	}
	resp, err := c.PostAndGetRawResponse(&RESTRequest{Service: ServiceLLMApps, Path: "chat", Data: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if requests != 2 {
		t.Fatalf("GET and POST must both use wrapper: requests=%d", requests)
	}
}

func TestClientOptionsDefaultsAndInvalidSettings(t *testing.T) {
	defaultTransport := http.DefaultTransport
	var seen http.RoundTripper
	c, err := NewClientWithOptions("https://one.example", NewNullAuth(), ClientOptions{
		WrapTransport: func(base http.RoundTripper) http.RoundTripper { seen = base; return base },
	})
	if err != nil || c == nil || seen != defaultTransport || http.DefaultTransport != defaultTransport {
		t.Fatalf("default transport handling: client=%v err=%v", c, err)
	}
	for _, tc := range []struct {
		name string
		auth AuthProvider
		opts ClientOptions
	}{
		{"missing auth", nil, ClientOptions{}},
		{"empty address", NewNullAuth(), ClientOptions{}},
		{"nil wrapper result", NewNullAuth(), ClientOptions{WrapTransport: func(http.RoundTripper) http.RoundTripper { return nil }}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address := "https://one.example"
			if tc.name == "empty address" {
				address = ""
			}
			if got, err := NewClientWithOptions(address, tc.auth, tc.opts); err == nil || got != nil {
				t.Fatal("invalid settings must fail construction")
			}
		})
	}
	caller := &http.Client{Transport: optionsRoundTripper(func(r *http.Request) (*http.Response, error) { return optionsResponse(r), nil })}
	c, err = NewClientWithOptions("https://one.example", NewNullAuth(), ClientOptions{HTTPClient: caller})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.GetURL(ServiceLLMApps, "chat"); err != nil {
		t.Fatal(err)
	}
}

func TestNewClientWithOptionsRejectsInvalidAddress(t *testing.T) {
	for _, address := range []string{"", "one.example", "/api", "ftp://one.example", "https://", "http://:8080"} {
		if c, err := NewClientWithOptions(address, NewNullAuth(), ClientOptions{}); err == nil || c != nil {
			t.Errorf("address %q: want error", address)
		}
	}
	if _, err := NewClientWithOptions("http://127.0.0.1:8080", NewNullAuth(), ClientOptions{}); err != nil {
		t.Errorf("valid address rejected: %v", err)
	}
}

func TestClientOptionsConcurrentIsolation(t *testing.T) {
	shared := &http.Client{Timeout: time.Second}
	errs := make(chan error, 20)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host, token := fmt.Sprintf("client-%d.example", i), fmt.Sprintf("key-%d", i)
			c, err := NewClientWithOptions("https://"+host, NewAPITokenAuth(token), ClientOptions{
				HTTPClient: shared,
				WrapTransport: func(http.RoundTripper) http.RoundTripper {
					return optionsRoundTripper(func(r *http.Request) (*http.Response, error) {
						if r.URL.Host != host || r.Header.Get("Authorization") != "NIRMATA-API "+token {
							return nil, fmt.Errorf("cross-client configuration leak")
						}
						return optionsResponse(r), nil
					})
				},
			})
			if err == nil {
				_, _, err = c.GetURL(ServiceLLMApps, "chat")
			}
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if shared.Transport != nil || shared.Timeout != time.Second {
		t.Fatal("shared caller HTTP client was mutated")
	}
}

func TestLegacyConstructorsUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    Client
		want string
	}{
		{"api", NewClientWithAPIKey("https://one.example", "api", false), "NIRMATA-API api"},
		{"jwt", NewClientWithJWTToken("https://one.example", "jwt", false), "Bearer jwt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodGet, "https://one.example", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.c.(*client).SetAuthorizationHeader(r); err != nil {
				t.Fatal(err)
			}
			if r.Header.Get("Authorization") != tc.want || tc.c.(*client).httpClient.Transport != nil {
				t.Fatal("legacy auth or default transport changed")
			}
		})
	}
	c := NewClientWithServiceAccountToken("https://one.example", "sa", "id", true).(*client)
	if _, ok := c.authProvider.(*ServiceAccountTokenAuth); !ok {
		t.Fatal("legacy service account auth changed")
	}
	if !c.httpClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
		t.Fatal("legacy insecure option changed")
	}
}
