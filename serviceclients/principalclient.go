package serviceclients

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nirmata/go-client"
	"k8s.io/klog/v2"
)

const (
	whoamiPath       = "whoami"
	principalTimeout = 30 * time.Second
	maxPrincipalBody = 1 << 20
)

// Principal is the caller of an API key as resolved by the users service realm.
// TenantID is the tenant the credential acts in.
type Principal struct {
	ID            string
	Email         string
	Name          string
	Role          string
	TenantID      string
	CompanyID     string
	PrincipalType string
}

// PrincipalClientConfig configures GetCurrentPrincipal.
type PrincipalClientConfig struct {
	// Address is the base URL. "https://" selects the in-cluster users service.
	Address string
	// HTTPClient overrides the default client, for example a SPIRE mTLS transport.
	// When nil, certificates are verified, except for the in-cluster address, as ServiceClient does.
	HTTPClient *http.Client
}

type principalResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	Role          string `json:"role"`
	TenantID      string `json:"tenantId"`
	CompanyID     string `json:"companyId"`
	PrincipalType string `json:"principalType"`
}

// GetCurrentPrincipal returns the principal the users service resolves for apiKey.
// The key is sent only as "Authorization: NIRMATA-API <key>" to GET /users/api/whoami,
// so the users service authenticates it with the same realm as every other API call.
func GetCurrentPrincipal(apiKey string, cfg PrincipalClientConfig) (Principal, error) {
	if apiKey == "" {
		return Principal{}, fmt.Errorf("API key is required")
	}

	address := cfg.Address
	if address == "" {
		address = "https://"
	}
	// Same builder the other service calls use, so "https://" resolves to https://users/users/api/...
	target := client.NewURLBuilder(address).ToService(client.ServiceUsers).WithPath(whoamiPath).Build()

	ctx, cancel := context.WithTimeout(context.Background(), principalTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Principal{}, fmt.Errorf("failed to create request: %w", err)
	}
	if aerr := client.NewAPITokenAuth(apiKey).SetAuthHeader(req); aerr != nil {
		return Principal{}, fmt.Errorf("failed to set authorization header: %w", aerr)
	}
	req.Header.Set("Accept", "application/json")

	var httpClient http.Client
	switch {
	case cfg.HTTPClient != nil:
		httpClient = *cfg.HTTPClient // copy: the caller's client is not modified
	case client.IsInternalBaseURL(address):
		// The in-cluster users service presents a cluster-internal certificate (same as ServiceClient).
		httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	}
	// Any other address uses http.DefaultTransport, which verifies the certificate the key is sent to.
	// The key must never follow a redirect to another host or scheme.
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	klog.V(3).Infof("GetCurrentPrincipal GET %s", target)
	resp, err := httpClient.Do(req)
	if err != nil {
		return Principal{}, fmt.Errorf("failed to reach users service: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPrincipalBody))
	if err != nil {
		return Principal{}, fmt.Errorf("failed to read response: %w", err)
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
	case resp.StatusCode == http.StatusNotFound:
		return Principal{}, fmt.Errorf(
			"users service does not expose whoami yet; deploy a newer users service (status: %d)", resp.StatusCode)
	case resp.StatusCode >= 300 && resp.StatusCode <= 399:
		return Principal{}, fmt.Errorf("users redirected the request; redirects are refused (status: %d)", resp.StatusCode)
	case resp.StatusCode >= 500:
		return Principal{}, fmt.Errorf("users service error: %s (status: %d)", resp.Status, resp.StatusCode)
	default:
		return Principal{}, fmt.Errorf("users rejected the credential: %s (status: %d)", resp.Status, resp.StatusCode)
	}

	var p principalResponse
	if err := json.Unmarshal(body, &p); err != nil {
		return Principal{}, fmt.Errorf("failed to parse response: %w", err)
	}

	return Principal(p), nil
}
