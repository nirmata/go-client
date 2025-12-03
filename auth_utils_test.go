package client

import (
	"testing"
)

func TestExchangeServiceAccountTokenForJWTToken_Success(t *testing.T) {
	// Real server credentials
	address := "https://devtest2.nirmata.co"
	serviceAccountToken := "910a4190-d428-4eec-b890-59911d107b48"
	clientID := "clientId"

	// Test the function with real server
	token, err := exchangeServiceAccountTokenForJWTToken(serviceAccountToken, address, clientID)

	// Verify the result
	if err != nil {
		t.Fatalf("Failed to exchange service account token for JWT: %v", err)
	}

	// Verify we got a non-empty JWT token
	if token == "" {
		t.Fatal("Expected a non-empty JWT token, got empty string")
	}

	t.Logf("Successfully obtained JWT token (length: %d characters)", len(token))

	// Show token preview (first 20 chars or full token if shorter)
	previewLen := 20
	if len(token) < previewLen {
		previewLen = len(token)
	}
	t.Logf("Token preview: %s...", token[:previewLen])
}
