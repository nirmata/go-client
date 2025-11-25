package client

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"k8s.io/klog/v2"
)

const (
	// DefaultServiceAccountTokenPath is the default path where Kubernetes mounts service account tokens
	DefaultServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	// ServiceAccountAuthScheme is the authorization scheme for service account tokens
	ServiceAccountAuthScheme = "NIRMATA-SERVICEACCOUNT"
)

// ServiceClient provides authenticated access to other Nirmata services using Kubernetes Service Account tokens
// This is specifically for service-to-service communication in Kubernetes environments
type ServiceClient struct {
	service    Service
	address    string
	httpClient *http.Client
	saToken    string
}

// ServiceClientConfig holds configuration for creating a ServiceClient
type ServiceClientConfig struct {
	// Service is the target service (e.g., ServiceUsers, ServiceClusters)
	Service Service

	// Address is the base address for service URLs (e.g., "https://", "https://example.com")
	// If "https://" or "http://", the service name will be injected (Kubernetes pattern)
	// Defaults to "https://" if empty
	Address string

	// ServiceAccountTokenPath is the path to the service account token file
	// If empty, uses DefaultServiceAccountTokenPath
	ServiceAccountTokenPath string

	// Insecure skips TLS certificate verification.
	// For internal service-to-service communication, this matches Java's behavior
	// where DnsServiceClient uses a "trust all" TrustManager.
	// Traffic is still encrypted via TLS, only certificate verification is skipped.
	Insecure bool
}

// NewServiceClient creates a new ServiceClient for service-to-service communication
// This follows the same URL patterns as the regular Client but uses ServiceAccount tokens for auth
func NewServiceClient(config ServiceClientConfig) (*ServiceClient, error) {
	if config.Service == 0 {
		return nil, fmt.Errorf("service is required for ServiceClient")
	}

	// Default to internal Kubernetes pattern
	address := config.Address
	if address == "" {
		address = "https://"
	}
	if !strings.HasSuffix(address, "/") {
		address = address + "/"
	}

	// Read service account token
	tokenPath := config.ServiceAccountTokenPath
	if tokenPath == "" {
		tokenPath = DefaultServiceAccountTokenPath
	}

	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read service account token from %s: %w", tokenPath, err)
	}
	saToken := strings.TrimSpace(string(tokenBytes))

	// Create HTTP client
	// For internal service-to-service communication, we skip TLS verification
	// to match Java's DnsServiceClient behavior (which uses a "trust all" TrustManager).
	// Traffic is still encrypted via TLS.
	httpClient := &http.Client{}
	if config.Insecure {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
	}

	klog.V(2).Infof("Created ServiceClient: target=%s, address=%s, insecure=%v",
		config.Service.Name(), address, config.Insecure)

	return &ServiceClient{
		service:    config.Service,
		address:    address,
		httpClient: httpClient,
		saToken:    saToken,
	}, nil
}

// buildURL constructs a URL following the same pattern as the regular Client
// Pattern: {address}/{service-name}/{service-name}/api/{path}
// For "https://" address: https://{service-name}/{service-name}/api/{path}
func (sc *ServiceClient) buildURL(path string) string {
	serviceName := sc.service.Name()
	baseURL := sc.address

	// If internal address (https:// or http://), inject service name
	if IsInternalBaseURL(sc.address) {
		baseURL = sc.address + serviceName + "/"
	}

	// Build URL: {baseURL}/{service}/api/{path}
	return strings.TrimRight(baseURL, "/") + "/" + serviceName + "/api/" + strings.TrimPrefix(path, "/")
}

// Get performs a GET request to the target service
func (sc *ServiceClient) Get(path string) ([]byte, int, Error) {
	url := sc.buildURL(path)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, NewError("ErrorHTTP", fmt.Sprintf("failed to create request: %s", url), err)
	}

	// Add service account token authorization header
	req.Header.Add("Authorization", fmt.Sprintf("%s %s", ServiceAccountAuthScheme, sc.saToken))

	klog.V(3).Infof("ServiceClient GET %s", url)

	return sc.doRequest(req)
}

// Post performs a POST request to the target service
func (sc *ServiceClient) Post(path string, contentType string, data []byte) ([]byte, int, Error) {
	url := sc.buildURL(path)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return nil, 0, NewError("ErrorHTTP", fmt.Sprintf("failed to create request: %s", url), err)
	}

	// Add service account token authorization header
	req.Header.Add("Authorization", fmt.Sprintf("%s %s", ServiceAccountAuthScheme, sc.saToken))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	klog.V(3).Infof("ServiceClient POST %s", url)

	return sc.doRequest(req)
}

// Put performs a PUT request to the target service
func (sc *ServiceClient) Put(path string, contentType string, data []byte) ([]byte, int, Error) {
	url := sc.buildURL(path)

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(data))
	if err != nil {
		return nil, 0, NewError("ErrorHTTP", fmt.Sprintf("failed to create request: %s", url), err)
	}

	// Add service account token authorization header
	req.Header.Add("Authorization", fmt.Sprintf("%s %s", ServiceAccountAuthScheme, sc.saToken))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	klog.V(3).Infof("ServiceClient PUT %s", url)

	return sc.doRequest(req)
}

// Delete performs a DELETE request to the target service
func (sc *ServiceClient) Delete(path string) ([]byte, int, Error) {
	url := sc.buildURL(path)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return nil, 0, NewError("ErrorHTTP", fmt.Sprintf("failed to create request: %s", url), err)
	}

	// Add service account token authorization header
	req.Header.Add("Authorization", fmt.Sprintf("%s %s", ServiceAccountAuthScheme, sc.saToken))

	klog.V(3).Infof("ServiceClient DELETE %s", url)

	return sc.doRequest(req)
}

// doRequest executes the HTTP request and handles the response
func (sc *ServiceClient) doRequest(req *http.Request) ([]byte, int, Error) {
	resp, err := sc.httpClient.Do(req)
	if err != nil {
		return nil, 0, NewError("ErrorHTTP", fmt.Sprintf("HTTP %s request %s", req.Method, req.URL.String()), err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, NewError("ErrorHTTP", fmt.Sprintf("failed to read response body from %s", req.URL.String()), err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		klog.V(1).Infof("ServiceClient HTTP %d '%s': %s", resp.StatusCode, resp.Status, string(body))
		return body, resp.StatusCode, NewError("ErrorHTTP", fmt.Sprintf("%s: %s", resp.Status, string(body)), nil)
	}

	klog.V(3).Infof("ServiceClient response status=%s length=%d", resp.Status, len(body))
	return body, resp.StatusCode, nil
}

// Service returns the target service
func (sc *ServiceClient) Service() Service {
	return sc.service
}
