package serviceclients

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nirmata/go-client"
	"k8s.io/klog/v2"
)

const whoamiPath = "whoami"

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
	// When nil, a client with InsecureSkipVerify=true is used, as ServiceClient does.
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
	name := client.ServiceUsers.Name()
	base := strings.TrimRight(address, "/")
	if client.IsInternalBaseURL(address) {
		base = strings.TrimRight(address, "/") + "/" + name
	}
	target := base + "/" + name + "/api/" + whoamiPath

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return Principal{}, fmt.Errorf("failed to create request: %w", err)
	}
	if aerr := client.NewAPITokenAuth(apiKey).SetAuthHeader(req); aerr != nil {
		return Principal{}, fmt.Errorf("failed to set authorization header: %w", aerr)
	}
	req.Header.Set("Accept", "application/json")

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
		}
	}

	klog.V(3).Infof("GetCurrentPrincipal GET %s", target)
	resp, err := httpClient.Do(req)
	if err != nil {
		return Principal{}, fmt.Errorf("failed to reach users service: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Principal{}, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if resp.StatusCode == http.StatusNotFound {
			return Principal{}, fmt.Errorf(
				"users service does not expose whoami yet; deploy a users release that serves /users/api/whoami (status: %d)",
				resp.StatusCode)
		}
		return Principal{}, fmt.Errorf("users rejected the credential: %s (status: %d)", resp.Status, resp.StatusCode)
	}

	var p principalResponse
	if err := json.Unmarshal(body, &p); err != nil {
		return Principal{}, fmt.Errorf("failed to parse response: %w", err)
	}

	return Principal(p), nil
}
