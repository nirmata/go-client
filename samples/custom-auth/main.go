package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/nirmata/go-client"
)

// CustomAuth is an example of a custom authentication provider
// This example implements a simple auth provider that adds multiple headers
type CustomAuth struct {
	apiKey    string
	userAgent string
	timestamp time.Time
}

// NewCustomAuth creates a new custom authentication provider
func NewCustomAuth(apiKey, userAgent string) client.AuthProvider {
	return &CustomAuth{
		apiKey:    apiKey,
		userAgent: userAgent,
		timestamp: time.Now(),
	}
}

// SetAuthHeader implements the AuthProvider interface
func (a *CustomAuth) SetAuthHeader(req *http.Request) client.Error {
	// Add the authorization header
	req.Header.Add("Authorization", fmt.Sprintf("Custom-Token %s", a.apiKey))

	// Add custom headers
	req.Header.Add("X-User-Agent", a.userAgent)
	req.Header.Add("X-Auth-Timestamp", a.timestamp.Format(time.RFC3339))
	req.Header.Add("X-Custom-Auth", "true")

	fmt.Printf("[CustomAuth] Setting auth headers for request to: %s\n", req.URL.Path)

	return nil
}

// RotatingAuth is a more advanced example that refreshes tokens
type RotatingAuth struct {
	currentToken string
	refreshFunc  func() (string, error)
	lastRefresh  time.Time
	refreshAfter time.Duration
}

// NewRotatingAuth creates an authentication provider that refreshes tokens
func NewRotatingAuth(initialToken string, refreshFunc func() (string, error), refreshAfter time.Duration) client.AuthProvider {
	return &RotatingAuth{
		currentToken: initialToken,
		refreshFunc:  refreshFunc,
		lastRefresh:  time.Now(),
		refreshAfter: refreshAfter,
	}
}

// SetAuthHeader implements the AuthProvider interface with token rotation
func (a *RotatingAuth) SetAuthHeader(req *http.Request) client.Error {
	// Check if we need to refresh the token
	if time.Since(a.lastRefresh) > a.refreshAfter {
		fmt.Println("[RotatingAuth] Token expired, refreshing...")
		newToken, err := a.refreshFunc()
		if err != nil {
			return client.NewError("ErrorAuth", "Failed to refresh token", err)
		}
		a.currentToken = newToken
		a.lastRefresh = time.Now()
		fmt.Println("[RotatingAuth] Token refreshed successfully")
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", a.currentToken))
	return nil
}

func main() {
	// Get configuration from environment variables
	address := os.Getenv("NIRMATA_URL")
	apiToken := os.Getenv("NIRMATA_API_TOKEN")

	if address == "" || apiToken == "" {
		fmt.Println("Error: NIRMATA_URL and NIRMATA_API_TOKEN environment variables must be set")
		os.Exit(1)
	}

	// Example 1: Using CustomAuth
	fmt.Println("Example 1: Custom Authentication with Multiple Headers")
	fmt.Println("======================================================")

	customAuth := NewCustomAuth(apiToken, "MyCustomApp/1.0")
	customClient := client.NewClient(address, customAuth, false)

	fmt.Printf("Client created with custom auth provider\n")
	fmt.Printf("Address: %s\n\n", customClient.Address())

	// Note: This will fail unless your backend accepts "Custom-Token" format
	// This is just to demonstrate the concept
	fmt.Println("Note: This custom auth format is for demonstration purposes.")
	fmt.Println("Your backend would need to support the custom header format.\n")

	// Example 2: Using RotatingAuth
	fmt.Println("Example 2: Rotating Token Authentication")
	fmt.Println("=========================================")

	// Define a token refresh function
	refreshFunc := func() (string, error) {
		// In a real application, this would fetch a new token from an auth server
		fmt.Println("  → Fetching new token from auth server...")
		time.Sleep(100 * time.Millisecond) // Simulate network delay

		// For this example, we'll just return the same token
		// In production, you'd make an HTTP request to get a new token
		return apiToken, nil
	}

	// Create a rotating auth provider that refreshes every 30 seconds
	rotatingAuth := NewRotatingAuth(apiToken, refreshFunc, 30*time.Second)
	rotatingClient := client.NewClient(address, rotatingAuth, false)

	fmt.Printf("Client created with rotating auth provider\n")
	fmt.Printf("Token will refresh every 30 seconds\n")
	fmt.Printf("Address: %s\n\n", rotatingClient.Address())

	// Make a request with standard API token auth to verify everything works
	fmt.Println("Example 3: Using Standard Auth for Actual Request")
	fmt.Println("==================================================")

	standardClient := client.NewClientWithAPIKey(address, apiToken, false)

	envs, err := standardClient.GetCollection(client.ServiceEnvironments, "environments", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Successfully fetched %d environments\n", len(envs))

	fmt.Println("\n======================================================================")
	fmt.Println("Key Takeaways:")
	fmt.Println("======================================================================")
	fmt.Println("1. Custom auth providers must implement the AuthProvider interface")
	fmt.Println("2. The SetAuthHeader method receives the HTTP request and can modify headers")
	fmt.Println("3. You can implement any authentication logic (rotation, refresh, multi-header, etc.)")
	fmt.Println("4. Custom providers integrate seamlessly with the client")
	fmt.Println("======================================================================")
}
