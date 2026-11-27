package serviceclients

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testKey = "k3y+with/special=chars"

func TestGetCurrentPrincipal(t *testing.T) {
	var gotPath, gotAuth, gotQuery, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotQuery, gotMethod = r.URL.Path, r.Header.Get("Authorization"), r.URL.RawQuery, r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u1","email":"a@example.com","name":"A","role":"admin",` +
			`"tenantId":"t2","companyId":"c1","principalType":"User"}`))
	}))
	defer srv.Close()

	p, err := GetCurrentPrincipal(testKey, PrincipalClientConfig{Address: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/users/api/whoami" {
		t.Errorf("request = %s %s, want GET /users/api/whoami", gotMethod, gotPath)
	}
	if gotAuth != "NIRMATA-API "+testKey {
		t.Errorf("Authorization = %q, want NIRMATA-API <key>", gotAuth)
	}
	if strings.Contains(gotAuth, "SERVICEACCOUNT") {
		t.Errorf("sent a service-account credential: %q", gotAuth)
	}
	if gotQuery != "" {
		t.Errorf("query = %q, want none", gotQuery)
	}
	want := Principal{ID: "u1", Email: "a@example.com", Name: "A", Role: "admin",
		TenantID: "t2", CompanyID: "c1", PrincipalType: "User"}
	if p != want {
		t.Errorf("principal = %+v, want %+v", p, want)
	}
}

func TestGetCurrentPrincipalKeyNeverInURL(t *testing.T) {
	var gotURI string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI = r.RequestURI
		_, _ = w.Write([]byte(`{"id":"u1","tenantId":"t1"}`))
	}))
	defer srv.Close()

	if _, err := GetCurrentPrincipal(testKey, PrincipalClientConfig{Address: srv.URL, HTTPClient: srv.Client()}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(gotURI, "k3y") {
		t.Errorf("key leaked into URL: %q", gotURI)
	}
}

func TestGetCurrentPrincipalErrors(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		wantMsg string
	}{
		{"unauthorized", http.StatusUnauthorized, "users rejected the credential"},
		{"forbidden", http.StatusForbidden, "users rejected the credential"},
		{"old users image", http.StatusNotFound, "does not expose whoami"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(`{"message":"nope"}`))
			}))
			defer srv.Close()

			_, err := GetCurrentPrincipal(testKey, PrincipalClientConfig{Address: srv.URL, HTTPClient: srv.Client()})
			if err == nil || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantMsg)
			}
			if strings.Contains(err.Error(), "k3y") {
				t.Errorf("error leaks the key: %v", err)
			}
		})
	}
}

func TestGetCurrentPrincipalRejectsEmptyKey(t *testing.T) {
	if _, err := GetCurrentPrincipal("", PrincipalClientConfig{Address: "http://127.0.0.1:1"}); err == nil {
		t.Fatal("want error for empty key")
	}
}

func TestGetCurrentPrincipalBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	if _, err := GetCurrentPrincipal(testKey, PrincipalClientConfig{Address: srv.URL, HTTPClient: srv.Client()}); err == nil {
		t.Fatal("want parse error")
	}
}
