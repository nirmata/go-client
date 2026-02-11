package client

import (
	"k8s.io/klog/v2"
)

func exchangeServiceAccountTokenForJWTToken(serviceAccountToken string, address string, clientid string) (string, Error) {
	// Create a client with NullAuth since this endpoint doesn't require authentication
	// Use insecure=true for internal Kubernetes service communication where certificates may be self-signed
	c := NewClient(address, NewNullAuth(), true)

	klog.V(3).Infof("Exchanging service account token for JWT")

	// Prepare the request data
	requestData := map[string]interface{}{
		"grant_type":    "client_credentials",
		"client_id":     clientid,
		"client_secret": serviceAccountToken,
	}

	// Use the client's PostFromJSON method to make the request
	response, err := c.PostFromJSON(ServiceSecurity, "auth/token", requestData, nil)
	if err != nil {
		return "", NewError("ErrorHTTP", "Failed to exchange service account token for JWT", err)
	}

	// Extract the access_token from the response
	if token, ok := response["access_token"].(string); ok && token != "" {
		klog.V(3).Infof("Successfully exchanged service account token for JWT")
		return token, nil
	}

	return "", NewError("ErrorHTTP", "No access_token found in response", nil)
}
