package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang/glog"
)

func IsJwtTokenExpired(jwtToken string) bool {
	payload, err := getJWTPayload(jwtToken)
	if err != nil {
		glog.Errorf("Failed to get JWT payload: %s", err)
		return true
	}

	expTime, err := getExpiryTimeFromJWT(payload)
	if err != nil {
		glog.Errorf("Failed to get expiry time from JWT: %s", err)
		return true
	}

	return float64(time.Now().Unix()) >= expTime
}

func getJWTPayload(jwtToken string) ([]byte, error) {
	// JWT will have 3 parts: header, payload, signature
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		glog.Errorf("Invalid JWT token: %s", jwtToken)
		return nil, fmt.Errorf("invalid JWT token")
	}

	payload := parts[1]
	// Add padding if necessary for base64 decoding
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decodedPayload, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %s", err)
	}

	return decodedPayload, nil
}

func getExpiryTimeFromJWT(payload []byte) (float64, error) {
	var claims map[string]interface{}
	err := json.Unmarshal(payload, &claims)
	if err != nil {
		return 0, fmt.Errorf("failed to parse JWT payload: %s", err)
	}

	exp, exists := claims["exp"]
	if !exists {
		return 0, fmt.Errorf("no expiration claim found in JWT payload")
	}

	expTime, ok := exp.(float64)
	if !ok {
		return 0, fmt.Errorf("invalid expiration claim format in JWT payload")
	}

	return expTime, nil
}
