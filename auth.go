package client

import (
	"fmt"
	"net/http"
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
	serviceAccountToken string

	/*The JWT token is fetched using the
	service account token and is short lived
	*/
	jwtToken string
}

func NewServiceAccountTokenAuth(serviceAccountToken string) AuthProvider {
	return &ServiceAccountTokenAuth{serviceAccountToken: serviceAccountToken, jwtToken: ""}
}

func (a *ServiceAccountTokenAuth) SetAuthHeader(req *http.Request) Error {
	if a.jwtToken == "" || IsJwtTokenExpired(a.jwtToken) {
		jwtToken, err := a.FetchJWTToken()
		if err != nil {
			return err
		}
		a.jwtToken = jwtToken
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", a.jwtToken))
	return nil
}

func (a *ServiceAccountTokenAuth) FetchJWTToken() (string, Error) {
	// Fetch the JWT token using the service account token
	// TODO: Implement custom logic for fetching the JWT token
	return "placeHolder", nil
}
