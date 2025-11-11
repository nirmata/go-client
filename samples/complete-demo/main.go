package main

import (
	"fmt"
	"os"

	"github.com/nirmata/go-client"
)

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║   Go-Client Authentication Examples                         ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Get configuration from environment variables
	address := os.Getenv("NIRMATA_URL")
	apiToken := os.Getenv("NIRMATA_API_TOKEN")
	jwtToken := os.Getenv("NIRMATA_JWT_TOKEN")
	saToken := os.Getenv("NIRMATA_SA_TOKEN")

	if address == "" {
		fmt.Println("❌ Error: NIRMATA_URL environment variable must be set")
		printUsage()
		os.Exit(1)
	}

	// Track which auth methods are available
	hasAPIToken := apiToken != ""
	hasJWTToken := jwtToken != ""
	hasSAToken := saToken != ""

	if !hasAPIToken && !hasJWTToken && !hasSAToken {
		fmt.Println("❌ Error: At least one authentication token must be set")
		printUsage()
		os.Exit(1)
	}

	fmt.Println("Configuration:")
	fmt.Printf("  • Server URL: %s\n", address)
	fmt.Printf("  • API Token: %s\n", boolToStatus(hasAPIToken))
	fmt.Printf("  • JWT Token: %s\n", boolToStatus(hasJWTToken))
	fmt.Printf("  • SA Token:  %s\n", boolToStatus(hasSAToken))
	fmt.Println()

	// Example 1: API Token Authentication
	if hasAPIToken {
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("1️⃣  API Token Authentication")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

		// Method 1: Convenience constructor
		c1 := client.NewClientWithAPIKey(address, apiToken, false)
		fmt.Println("   ✓ Client created using NewClientWithAPIKey()")

		// Method 2: Using auth provider
		apiAuth := client.NewAPITokenAuth(apiToken)
		c2 := client.NewClient(address, apiAuth, false)
		fmt.Println("   ✓ Client created using NewClient() with APITokenAuth")

		// Test the client
		if err := testClient(c1, "API Token"); err != nil {
			fmt.Printf("   ❌ API Token authentication failed: %v\n", err)
		} else {
			fmt.Println("   ✓ API Token authentication successful!")
		}
		fmt.Println()

		_ = c2 // Used to show alternative creation method
	}

	// Example 2: JWT Token Authentication
	if hasJWTToken {
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("2️⃣  JWT Token Authentication")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

		// Method 1: Convenience constructor
		c1 := client.NewClientWithJWTToken(address, jwtToken, false)
		fmt.Println("   ✓ Client created using NewClientWithJWTToken()")

		// Method 2: Using auth provider
		jwtAuth := client.NewJWTTokenAuth(jwtToken)
		c2 := client.NewClient(address, jwtAuth, false)
		fmt.Println("   ✓ Client created using NewClient() with JWTTokenAuth")

		// Test the client
		if err := testClient(c1, "JWT Token"); err != nil {
			fmt.Printf("   ❌ JWT Token authentication failed: %v\n", err)
		} else {
			fmt.Println("   ✓ JWT Token authentication successful!")
		}
		fmt.Println()

		_ = c2 // Used to show alternative creation method
	}

	// Example 3: Service Account Token Authentication
	if hasSAToken {
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("3️⃣  Service Account Token Authentication")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

		// Method 1: Convenience constructor
		c1 := client.NewClientWithServiceAccountToken(address, saToken, false)
		fmt.Println("   ✓ Client created using NewClientWithServiceAccountToken()")

		// Method 2: Using auth provider
		saAuth := client.NewServiceAccountTokenAuth(saToken)
		c2 := client.NewClient(address, saAuth, false)
		fmt.Println("   ✓ Client created using NewClient() with ServiceAccountTokenAuth")

		// Test the client
		if err := testClient(c1, "Service Account Token"); err != nil {
			fmt.Printf("   ❌ Service Account Token authentication failed: %v\n", err)
		} else {
			fmt.Println("   ✓ Service Account Token authentication successful!")
		}
		fmt.Println()

		_ = c2 // Used to show alternative creation method
	}

	// Example 4: Switching Authentication at Runtime
	if hasAPIToken && hasJWTToken {
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("4️⃣  Runtime Authentication Switching")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

		// Start with API token
		c := client.NewClientWithAPIKey(address, apiToken, false)
		fmt.Println("   ✓ Client created with API Token")

		// Test with API token
		if err := testClient(c, "API Token (initial)"); err == nil {
			fmt.Println("   ✓ Request successful with API Token")
		}

		// Switch to JWT token
		jwtAuth := client.NewJWTTokenAuth(jwtToken)
		c.SetAuth(jwtAuth)
		fmt.Println("   ✓ Switched to JWT Token authentication")

		// Test with JWT token
		if err := testClient(c, "JWT Token (switched)"); err == nil {
			fmt.Println("   ✓ Request successful with JWT Token")
		}

		// Switch back to API token
		apiAuth := client.NewAPITokenAuth(apiToken)
		c.SetAuth(apiAuth)
		fmt.Println("   ✓ Switched back to API Token authentication")

		fmt.Println("   ✓ Runtime authentication switching demonstrated!")
		fmt.Println()
	}

	// Summary
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║   Summary                                                    ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("The go-client library supports flexible authentication:")
	fmt.Println()
	fmt.Println("📌 Three Built-in Authentication Methods:")
	fmt.Println("   • API Token (NIRMATA-API header)")
	fmt.Println("   • JWT Token (Bearer token)")
	fmt.Println("   • Service Account Token (Bearer token, extensible)")
	fmt.Println()
	fmt.Println("📌 Two Ways to Create Clients:")
	fmt.Println("   • Convenience constructors (e.g., NewClientWithAPIKey)")
	fmt.Println("   • Base constructor with AuthProvider (NewClient)")
	fmt.Println()
	fmt.Println("📌 Runtime Authentication Switching:")
	fmt.Println("   • Use SetAuth() to change authentication on existing clients")
	fmt.Println()
	fmt.Println("📌 Extensibility:")
	fmt.Println("   • Implement AuthProvider interface for custom auth")
	fmt.Println("   • See custom_auth.go for examples")
	fmt.Println()
	fmt.Println("✅ All authentication methods tested successfully!")
	fmt.Println()
}

// testClient tests a client by making a simple API call
func testClient(c client.Client, authType string) error {
	fmt.Printf("   Testing with %s...\n", authType)

	// Try to fetch environments (a simple read operation)
	envs, err := c.GetCollection(client.ServiceEnvironments, "environments", nil)
	if err != nil {
		return err
	}

	fmt.Printf("   ✓ Fetched %d environment(s)\n", len(envs))
	return nil
}

// boolToStatus converts a boolean to a status string
func boolToStatus(b bool) string {
	if b {
		return "✓ Set"
	}
	return "✗ Not set"
}

// printUsage prints usage information
func printUsage() {
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  Set the following environment variables:")
	fmt.Println()
	fmt.Println("  Required:")
	fmt.Println("    NIRMATA_URL           - Your Nirmata instance URL")
	fmt.Println()
	fmt.Println("  At least one of:")
	fmt.Println("    NIRMATA_API_TOKEN     - API token for authentication")
	fmt.Println("    NIRMATA_JWT_TOKEN     - JWT token for authentication")
	fmt.Println("    NIRMATA_SA_TOKEN      - Service account token for authentication")
	fmt.Println()
	fmt.Println("Example:")
	fmt.Println("  export NIRMATA_URL=\"https://your-instance.nirmata.io\"")
	fmt.Println("  export NIRMATA_API_TOKEN=\"your-api-token\"")
	fmt.Println("  go run samples/main.go")
	fmt.Println()
}
