package client

import (
	"fmt"
	"net/http"
	"net/url"
)

// ClientOptions supplies HTTP settings for one client. Neither HTTPClient nor its
// Transport is modified. The supplied transport and cookie jar remain shared;
// callers must not mutate them while requests are in flight.
type ClientOptions struct {
	HTTPClient *http.Client
	// WrapTransport decorates the effective base transport. For example, a caller
	// can supply authentication or tracing without coupling this SDK to it.
	WrapTransport func(http.RoundTripper) http.RoundTripper
}

// NewClientWithOptions constructs a client without consulting process environment
// variables. Authentication is explicit: use NewNullAuth when a transport supplies
// it. Construction makes no network requests.
// Existing constructors retain their behavior.
func NewClientWithOptions(address string, auth AuthProvider, opts ClientOptions) (Client, error) {
	u, err := url.Parse(address)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid address %q: must be an absolute http or https URL", address)
	}
	// API paths are appended to the raw address, so a query, fragment or
	// userinfo would swallow them or leak into every request URL.
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("invalid address %q: must not contain a query, fragment or user info", address)
	}
	if auth == nil {
		return nil, fmt.Errorf("auth provider is required; use NewNullAuth for transport authentication")
	}

	httpClient := new(http.Client)
	if opts.HTTPClient != nil {
		*httpClient = *opts.HTTPClient
	}
	if opts.WrapTransport != nil {
		base := httpClient.Transport
		if base == nil {
			base = http.DefaultTransport
		}
		wrapped := opts.WrapTransport(base)
		if wrapped == nil {
			return nil, fmt.Errorf("transport wrapper returned nil")
		}
		httpClient.Transport = wrapped
	}

	return &client{address: address, authProvider: auth, httpClient: httpClient}, nil
}
