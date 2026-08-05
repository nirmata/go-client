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
	DefaultServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	ServiceAccountAuthScheme       = "NIRMATA-SERVICEACCOUNT"
)

// ServiceClient provides authenticated access to Nirmata services using Kubernetes ServiceAccount tokens
type ServiceClient struct {
	service    Service
	address    string
	httpClient *http.Client
	saToken    string
}

// ServiceClientConfig holds configuration for creating a ServiceClient
type ServiceClientConfig struct {
	Service                 Service
	Address                 string // Base URL. Defaults to "https://" (internal K8s pattern)
	ServiceAccountTokenPath string // Defaults to /var/run/secrets/kubernetes.io/serviceaccount/token
	// HTTPClient overrides the default HTTP client. When set, the caller is
	// responsible for TLS configuration (e.g. a SPIRE mTLS transport).
	// When nil, a default client with InsecureSkipVerify=true is used.
	HTTPClient *http.Client
}

// NewServiceClient creates a new ServiceClient for service-to-service communication
func NewServiceClient(config ServiceClientConfig) (*ServiceClient, error) {
	if config.Service == 0 {
		return nil, fmt.Errorf("service is required")
	}

	address := config.Address
	if address == "" {
		address = "https://"
	}
	if !strings.HasSuffix(address, "/") {
		address = address + "/"
	}

	tokenPath := config.ServiceAccountTokenPath
	if tokenPath == "" {
		tokenPath = DefaultServiceAccountTokenPath
	}

	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read service account token from %s: %w", tokenPath, err)
	}
	saToken := strings.TrimSpace(string(tokenBytes))

	httpClient := config.HTTPClient
	if httpClient == nil {
		// Default: skip TLS verification for internal service-to-service
		// communication (matches Java behaviour). Callers that need mTLS
		// should supply a transport via ServiceClientConfig.HTTPClient.
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
		}
	}

	klog.V(2).Infof("Created ServiceClient: target=%s, address=%s", config.Service.Name(), address)

	return &ServiceClient{
		service:    config.Service,
		address:    address,
		httpClient: httpClient,
		saToken:    saToken,
	}, nil
}

func (sc *ServiceClient) buildURL(path string) string {
	serviceName := sc.service.Name()
	baseURL := sc.address

	if IsInternalBaseURL(sc.address) {
		baseURL = sc.address + serviceName + "/"
	}

	return strings.TrimRight(baseURL, "/") + "/" + serviceName + "/api/" + strings.TrimPrefix(path, "/")
}

func (sc *ServiceClient) Get(path string) ([]byte, int, Error) {
	url := sc.buildURL(path)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, NewError("ErrorHTTP", fmt.Sprintf("failed to create request: %s", url), err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("%s %s", ServiceAccountAuthScheme, sc.saToken))
	klog.V(3).Infof("ServiceClient GET service=%s", sc.service.Name())
	return sc.doRequest(req)
}

func (sc *ServiceClient) Post(path string, contentType string, data []byte) ([]byte, int, Error) {
	url := sc.buildURL(path)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return nil, 0, NewError("ErrorHTTP", fmt.Sprintf("failed to create request: %s", url), err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("%s %s", ServiceAccountAuthScheme, sc.saToken))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	klog.V(3).Infof("ServiceClient POST service=%s", sc.service.Name())
	return sc.doRequest(req)
}

func (sc *ServiceClient) Put(path string, contentType string, data []byte) ([]byte, int, Error) {
	url := sc.buildURL(path)

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(data))
	if err != nil {
		return nil, 0, NewError("ErrorHTTP", fmt.Sprintf("failed to create request: %s", url), err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("%s %s", ServiceAccountAuthScheme, sc.saToken))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	klog.V(3).Infof("ServiceClient PUT service=%s", sc.service.Name())
	return sc.doRequest(req)
}

func (sc *ServiceClient) Delete(path string) ([]byte, int, Error) {
	url := sc.buildURL(path)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return nil, 0, NewError("ErrorHTTP", fmt.Sprintf("failed to create request: %s", url), err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("%s %s", ServiceAccountAuthScheme, sc.saToken))
	klog.V(3).Infof("ServiceClient DELETE service=%s", sc.service.Name())
	return sc.doRequest(req)
}

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

func (sc *ServiceClient) Service() Service {
	return sc.service
}
