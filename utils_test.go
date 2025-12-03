package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestIsJwtTokenExpired_ValidNotExpiredToken(t *testing.T) {
	// expires on 1764166688
	jwtToken := "eyJhbGciOiJSUzI1NiJ9.eyJOYW1lIjoiYXJhc2gtdGVzdC0xMCIsInN1YiI6Ijk3MjI4ZTIzLTViOTMtNDdhZi1iNWJiLThjM2YzOTBlMGUwMiIsImlzcyI6IlNlY3VyaXR5IiwiYXVkIjoiIiwiUm9sZXMiOiJkZXZvcHMiLCJHcm91cHMiOiIiLCJUZW5hbnQgSUQiOiJiODUxODNkNC1mZmFhLTRiOTItOGI4Ny03ZWExYzc3YWZhYTQiLCJQcmluY2lwbGUgVHlwZSI6IlNlcnZpY2VBY2NvdW50IiwiZXhwIjoxNzY0MTY2Njg4fQ.jh5DzCIsYAk5NbsqSgWVYxU0JlDXTBTAmWWDj7saKV4B1l4aYSoaEm--h6uiyyc019TP_z2KHEwbjaZQNAFPoHYikDIWI_MYmkyDb-mj0oXJbU6AHcfKtruCmvluRRG-zf-7Y3zfrTJrHqls8Qi06AOZaaxF-HZsil_DrpdR83HaEN5SLizmu_aK8kpcxsgFZiuVAmgqcrsF4UrrSMAeO_-6BI8bj0q0x2pEvL_6-XswKBSsyc680k-Hnlrgkif9JAcCkT3QkVBJDlG8EZwAXZQ4R4girbdehts7pQ6YIPNdvrJX4Kt7F7EoEvUxv38wvr7VUX4I_MQsGfBiec_h5A"

	isExpired := IsJwtTokenExpired(jwtToken)

	// This token expires on March 26, 2025, so it should NOT be expired as of Nov 2024
	if isExpired {
		t.Error("Expected token to NOT be expired (expires in 2025), but got expired")
	}

	t.Logf("✓ Token is not expired (expires: 1764166688)")
}

func TestIsJwtTokenExpired_ExpiredToken(t *testing.T) {
	// Create a JWT token that expired in the past
	expiredToken := createTestJWT(time.Now().Add(-1 * time.Hour).Unix()) // Expired 1 hour ago

	isExpired := IsJwtTokenExpired(expiredToken)

	if !isExpired {
		t.Error("Expected token to be expired, but got not expired")
	}

	t.Logf("✓ Token is correctly identified as expired")
}

func TestIsJwtTokenExpired_TokenExpiringInFuture(t *testing.T) {
	// Create a JWT token that expires 1 hour from now
	futureToken := createTestJWT(time.Now().Add(1 * time.Hour).Unix())

	isExpired := IsJwtTokenExpired(futureToken)

	if isExpired {
		t.Error("Expected token to NOT be expired (expires in 1 hour), but got expired")
	}

	t.Logf("✓ Token expiring in future is correctly identified as not expired")
}

func TestIsJwtTokenExpired_TokenExpiringNow(t *testing.T) {
	// Create a JWT token that expires exactly now (edge case)
	nowToken := createTestJWT(time.Now().Unix())

	isExpired := IsJwtTokenExpired(nowToken)

	// Token expiring at current time should be considered expired
	if !isExpired {
		t.Error("Expected token expiring at current time to be expired, but got not expired")
	}

	t.Logf("✓ Token expiring at current time is correctly identified as expired")
}

func TestIsJwtTokenExpired_InvalidToken(t *testing.T) {
	// Invalid JWT format (not enough parts)
	invalidToken := "invalid.token"

	isExpired := IsJwtTokenExpired(invalidToken)

	// Invalid tokens should be treated as expired
	if !isExpired {
		t.Error("Expected invalid token to be treated as expired, but got not expired")
	}

	t.Logf("✓ Invalid token is correctly treated as expired")
}

func TestIsJwtTokenExpired_TokenWithoutExpField(t *testing.T) {
	// Create a JWT token without exp field
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test","name":"Test User"}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))
	tokenWithoutExp := fmt.Sprintf("%s.%s.%s", header, payload, signature)

	isExpired := IsJwtTokenExpired(tokenWithoutExp)

	// Token without exp field should be treated as expired
	if !isExpired {
		t.Error("Expected token without exp field to be treated as expired, but got not expired")
	}

	t.Logf("✓ Token without exp field is correctly treated as expired")
}

func TestIsJwtTokenExpired_EmptyToken(t *testing.T) {
	// Empty token string
	emptyToken := ""

	isExpired := IsJwtTokenExpired(emptyToken)

	// Empty token should be treated as expired
	if !isExpired {
		t.Error("Expected empty token to be treated as expired, but got not expired")
	}

	t.Logf("✓ Empty token is correctly treated as expired")
}

func TestIsJwtTokenExpired_TokenWithInvalidBase64(t *testing.T) {
	// Token with invalid base64 encoding
	invalidBase64Token := "header.@@invalid@@base64.signature"

	isExpired := IsJwtTokenExpired(invalidBase64Token)

	// Token with invalid base64 should be treated as expired
	if !isExpired {
		t.Error("Expected token with invalid base64 to be treated as expired, but got not expired")
	}

	t.Logf("✓ Token with invalid base64 is correctly treated as expired")
}

func TestIsJwtTokenExpired_TokenWithInvalidJSON(t *testing.T) {
	// Token with invalid JSON in payload
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{not valid json}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))
	invalidJSONToken := fmt.Sprintf("%s.%s.%s", header, payload, signature)

	isExpired := IsJwtTokenExpired(invalidJSONToken)

	// Token with invalid JSON should be treated as expired
	if !isExpired {
		t.Error("Expected token with invalid JSON to be treated as expired, but got not expired")
	}

	t.Logf("✓ Token with invalid JSON is correctly treated as expired")
}

func TestIsJwtTokenExpired_TokenWithStringExpField(t *testing.T) {
	// Token with exp as string instead of number
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test","exp":"not-a-number"}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))
	stringExpToken := fmt.Sprintf("%s.%s.%s", header, payload, signature)

	isExpired := IsJwtTokenExpired(stringExpToken)

	// Token with invalid exp format should be treated as expired
	if !isExpired {
		t.Error("Expected token with string exp field to be treated as expired, but got not expired")
	}

	t.Logf("✓ Token with invalid exp format is correctly treated as expired")
}

func TestIsJwtTokenExpired_TokenJustExpired(t *testing.T) {
	// Token that expired 1 second ago
	justExpiredToken := createTestJWT(time.Now().Add(-1 * time.Second).Unix())

	isExpired := IsJwtTokenExpired(justExpiredToken)

	if !isExpired {
		t.Error("Expected token expired 1 second ago to be expired, but got not expired")
	}

	t.Logf("✓ Token that just expired is correctly identified as expired")
}

func TestIsJwtTokenExpired_TokenExpiringFarInFuture(t *testing.T) {
	// Token that expires 1 year from now
	farFutureToken := createTestJWT(time.Now().Add(365 * 24 * time.Hour).Unix())

	isExpired := IsJwtTokenExpired(farFutureToken)

	if isExpired {
		t.Error("Expected token expiring in 1 year to NOT be expired, but got expired")
	}

	t.Logf("✓ Token expiring far in future is correctly identified as not expired")
}

// Helper function to create test JWT tokens with specific expiry times
func createTestJWT(expiryUnix int64) string {
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
	}

	payload := map[string]interface{}{
		"sub":  "test-user",
		"name": "Test User",
		"exp":  expiryUnix,
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signatureEncoded := base64.RawURLEncoding.EncodeToString([]byte("fake-signature-for-testing"))

	return fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, signatureEncoded)
}
