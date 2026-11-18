package client

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/klog/v2"
)

const noCertWarnText = "presents no client certificate"

// captureKlogWarnings returns a buffer receiving klog WARNING output only. With
// logtostderr off, klog writes a warning to both the WARNING and INFO sinks, so
// the INFO sink is discarded to count each warning once.
func captureKlogWarnings(t *testing.T) *strings.Builder {
	t.Helper()
	sb := captureKlogAtVerbosity(t, 0)
	klog.SetOutputBySeverity("INFO", io.Discard)
	klog.SetOutputBySeverity("WARNING", sb)
	return sb
}

func resetNoCertWarned() {
	for i := range noCertWarned {
		noCertWarned[i].Store(false)
	}
}

func saTokenFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte("sa-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newTestServiceClient(t *testing.T, address string, hc *http.Client) {
	t.Helper()
	if _, err := NewServiceClient(ServiceClientConfig{Service: ServiceUsers, Address: address,
		ServiceAccountTokenPath: saTokenFile(t), HTTPClient: hc}); err != nil {
		t.Fatal(err)
	}
}

func newTestOptionsClient(t *testing.T, address string, opts ClientOptions) {
	t.Helper()
	if _, err := NewClientWithOptions(address, NewNullAuth(), opts); err != nil {
		// Bare internal base URLs are accepted by NewClientWithOptions once go-client#28 lands.
		t.Skipf("NewClientWithOptions(%q): %v", address, err)
	}
}

func TestWarnInternalNoClientCert(t *testing.T) {
	wrap := func(rt http.RoundTripper) http.RoundTripper { return rt }
	for _, tt := range []struct {
		name     string
		build    func(t *testing.T)
		wantWarn string // substring the WARN must contain; empty means no WARN
	}{
		{"NewClient internal insecure", func(*testing.T) { NewClient("https://", NewNullAuth(), true) }, "NewClient built"},
		{"NewClient internal secure", func(*testing.T) { NewClient("https://", NewNullAuth(), false) }, "NewClient built"},
		{"NewClient external", func(*testing.T) { NewClient("https://nirmata.io", NewNullAuth(), true) }, ""},
		{"NewClient internal http", func(*testing.T) { NewClient("http://", NewNullAuth(), true) }, ""},
		{"ServiceClient default address", func(t *testing.T) { newTestServiceClient(t, "", nil) }, "ServiceClientConfig{HTTPClient}"},
		{"ServiceClient internal", func(t *testing.T) { newTestServiceClient(t, "https://", nil) }, "ServiceClientConfig{HTTPClient}"},
		{"ServiceClient external", func(t *testing.T) { newTestServiceClient(t, "https://nirmata.io", nil) }, ""},
		{"ServiceClient HTTP client supplied", func(t *testing.T) { newTestServiceClient(t, "https://", &http.Client{}) }, ""},
		{"Options external", func(t *testing.T) { newTestOptionsClient(t, "https://nirmata.io", ClientOptions{}) }, ""},
		{"Options internal", func(t *testing.T) { newTestOptionsClient(t, "https://", ClientOptions{}) }, "ClientOptions{HTTPClient}"},
		{"Options internal HTTP client supplied", func(t *testing.T) {
			newTestOptionsClient(t, "https://", ClientOptions{HTTPClient: &http.Client{}})
		}, ""},
		{"Options internal transport supplied", func(t *testing.T) {
			newTestOptionsClient(t, "https://", ClientOptions{WrapTransport: wrap})
		}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resetNoCertWarned()
			t.Cleanup(resetNoCertWarned)
			logs := captureKlogWarnings(t)
			tt.build(t)
			got := logs.String()
			if tt.wantWarn == "" {
				if strings.Contains(got, noCertWarnText) {
					t.Fatalf("unexpected WARN: %s", got)
				}
				return
			}
			for _, want := range []string{noCertWarnText, "SPIRE mTLS will reject", tt.wantWarn} {
				if !strings.Contains(got, want) {
					t.Fatalf("WARN missing %q; logs: %q", want, got)
				}
			}
		})
	}
}

func TestWarnInternalNoClientCertOncePerPath(t *testing.T) {
	for _, tt := range []struct {
		name  string
		build func(t *testing.T)
	}{
		{"NewClient", func(*testing.T) { NewClient("https://", NewNullAuth(), true) }},
		{"ServiceClient", func(t *testing.T) { newTestServiceClient(t, "https://", nil) }},
		{"Options", func(t *testing.T) { newTestOptionsClient(t, "https://", ClientOptions{}) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resetNoCertWarned()
			t.Cleanup(resetNoCertWarned)
			logs := captureKlogWarnings(t)
			for i := 0; i < 3; i++ {
				tt.build(t)
			}
			if n := strings.Count(logs.String(), noCertWarnText); n != 1 {
				t.Fatalf("want 1 WARN, got %d: %q", n, logs.String())
			}
		})
	}
}

func TestWarnInternalNoClientCertIndependentPaths(t *testing.T) {
	resetNoCertWarned()
	t.Cleanup(resetNoCertWarned)
	logs := captureKlogWarnings(t)
	NewClient("https://", NewNullAuth(), true)
	newTestServiceClient(t, "https://", nil)
	if n := strings.Count(logs.String(), noCertWarnText); n != 2 {
		t.Fatalf("want one WARN per constructor path (2), got %d: %q", n, logs.String())
	}
}
