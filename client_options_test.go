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

func TestNewClientWithOptionsAddressValidation(t *testing.T) {
	for _, tt := range []struct {
		address string
		valid   bool
	}{
		{"https://", true},
		{"http://", true},
		{"https://one.example", true},
		{"http://127.0.0.1:8080", true},
		{"", false},
		{"one.example", false},
		{"/api", false},
		{"ftp://one.example", false},
		{"ftp://", false},
		{"https:", false},
		{"https:///", false},
		{"https://?", false},
		{"http://:8080", false},
		{"https://one.example?tenant=one", false},
		{"https://one.example?", false},
		{"https://one.example#section", false},
		{"https://user:pw@one.example", false},
	} {
		t.Run(tt.address, func(t *testing.T) {
			c, err := NewClientWithOptions(tt.address, NewNullAuth(), ClientOptions{})
			if tt.valid && (err != nil || c == nil) {
				t.Fatalf("address %q: want valid, got err=%v", tt.address, err)
			}
			if !tt.valid && (err == nil || c != nil) {
				t.Fatalf("address %q: want error", tt.address)
			}
		})
	}
}

// recordingClient returns an *http.Client that records request URLs and answers
// every request with an empty JSON array.
func recordingClient(urls *[]string) *http.Client {
	return &http.Client{Transport: optionsRoundTripper(func(r *http.Request) (*http.Response, error) {
		*urls = append(*urls, r.Method+" "+r.URL.String())
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`[]`)), Request: r}, nil
	})}
}

func exerciseInternalCalls(t *testing.T, c Client) {
	t.Helper()
	if _, _, err := c.GetURL(ServicePolicies, "SlackChannel"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetCollection(ServicePolicies, "SlackChannel", nil); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Put(&RESTRequest{Service: ServicePolicies, Path: "SlackChannel/abc/postMessage",
		ContentType: "application/json", Data: []byte(`{}`)})
	if _, _, err := c.GetURL(ServiceUsers, "emails"); err != nil {
		t.Fatal(err)
	}
}

func TestClientOptionsInternalAddressMatchesLegacyURLs(t *testing.T) {
	for _, tt := range []struct {
		address string
		host    string
	}{
		{"https://", "https://policies/policies/api/"},
		{"http://", "http://policies/policies/api/"},
	} {
		t.Run(tt.address, func(t *testing.T) {
			var legacyURLs, optionURLs []string
			legacy := NewClient(tt.address, NewNullAuth(), false)
			legacy.(*client).httpClient = recordingClient(&legacyURLs)
			exerciseInternalCalls(t, legacy)

			opt, err := NewClientWithOptions(tt.address, NewNullAuth(), ClientOptions{HTTPClient: recordingClient(&optionURLs)})
			if err != nil {
				t.Fatal(err)
			}
			exerciseInternalCalls(t, opt)

			if len(optionURLs) != 4 || strings.Join(optionURLs, "\n") != strings.Join(legacyURLs, "\n") {
				t.Fatalf("URLs differ:\nlegacy:  %q\noptions: %q", legacyURLs, optionURLs)
			}
			if !strings.HasPrefix(strings.TrimPrefix(optionURLs[0], "GET "), tt.host) {
				t.Fatalf("want per-service DNS form %q, got %q", tt.host, optionURLs[0])
			}
		})
	}
}

func TestClientOptionsInternalAddressUsesSuppliedHTTPClient(t *testing.T) {
	var urls []string
	c, err := NewClientWithOptions("https://", NewJWTTokenAuth("jwt"), ClientOptions{HTTPClient: recordingClient(&urls)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetCollection(ServicePolicies, "SlackChannel", nil); err != nil {
		t.Fatal(err)
	}
	if len(urls) != 1 || !strings.HasPrefix(urls[0], "GET https://policies/policies/api/SlackChannel") {
		t.Fatalf("supplied HTTP client not used for internal address: %q", urls)
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

func TestServiceAccountTokenExchangeUsesHTTPClient(t *testing.T) {
	var paths []string
	var mu sync.Mutex
	effective := &http.Client{Transport: optionsRoundTripper(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "auth/token") {
			if r.Header.Get("Authorization") != "" {
				t.Errorf("token exchange sent Authorization %q", r.Header.Get("Authorization"))
			}
			resp := optionsResponse(r)
			resp.Header.Set("Content-Type", "application/json")
			resp.Body = io.NopCloser(strings.NewReader(`{"access_token":"exchanged"}`))
			return resp, nil
		}
		if got := r.Header.Get("Authorization"); got != "Bearer exchanged" {
			t.Errorf("API request Authorization = %q", got)
		}
		return optionsResponse(r), nil
	})}

	// The address is unreachable: every request must go through effective.
	const address = "https://unreachable.invalid"
	auth := NewServiceAccountTokenAuthWithHTTPClient("sa-token", address, "client", effective)
	c, err := NewClientWithOptions(address, auth, ClientOptions{HTTPClient: effective})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.GetURL(ServiceLLMApps, "chat"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 2 || !strings.HasSuffix(paths[0], "auth/token") {
		t.Fatalf("requests through the HTTP client: %v", paths)
	}
}
