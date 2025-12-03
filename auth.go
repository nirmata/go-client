package client

import (
	"fmt"
	"net/http"
	"sync"
)

type AuthProvider interface {
	SetAuthHeader(req *http.Request) Error
}

type APITokenAuth struct {
	token string
}

func NewAPITokenAuth(token string) AuthProvider {
	return &APITokenAuth{token: token}
}

func (a *APITokenAuth) SetAuthHeader(req *http.Request) Error {
	req.Header.Add("Authorization", fmt.Sprintf("NIRMATA-API %s", a.token))
	return nil
}

type JWTTokenAuth struct {
	token string
}

func NewJWTTokenAuth(token string) AuthProvider {
	return &JWTTokenAuth{token: token}
}

func (a *JWTTokenAuth) SetAuthHeader(req *http.Request) Error {
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", a.token))
	return nil
}

type ServiceAccountTokenAuth struct {
	Address             string
	serviceAccountToken string
	clientid            string

	/*The JWT token is fetched using the
	service account token and is short lived
	*/
	jwtToken string
	mu       sync.Mutex
}

func NewServiceAccountTokenAuth(serviceAccountToken string, address string, clientid string) AuthProvider {
	return &ServiceAccountTokenAuth{
		serviceAccountToken: serviceAccountToken,
		Address:             address,
		jwtToken:            "",
		clientid:            clientid,
	}
}

func (a *ServiceAccountTokenAuth) SetAuthHeader(req *http.Request) Error {
	if a.jwtToken == "" || IsJwtTokenExpired(a.jwtToken) {
		a.mu.Lock()
		jwtToken, err := a.fetchJWTToken()
		if err != nil {
			a.mu.Unlock()
			return NewError("ErrorHTTP", "Failed to fetch JWT token", err)
		}
		a.jwtToken = jwtToken
		a.mu.Unlock()
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", a.jwtToken))
	return nil
}

func (a *ServiceAccountTokenAuth) fetchJWTToken() (string, Error) {
	return exchangeServiceAccountTokenForJWTToken(a.serviceAccountToken, a.Address, a.clientid)
}

// NullAuth implements AuthProvider for no authentication
type NullAuth struct{}

// NewNullAuth creates a new null authentication provider that sets no auth headers
func NewNullAuth() AuthProvider {
	return &NullAuth{}
}

// SetAuthHeader does not set any authorization header
func (a *NullAuth) SetAuthHeader(req *http.Request) Error {
	// No authentication header is set
	return nil
}
