package main

import (
	"fmt"
	"os"

	"github.com/nirmata/go-client"
)

// This example demonstrates how to create a client with API token authentication
func main() {
	// Get configuration from environment variables
	address := os.Getenv("NIRMATA_URL")
	apiToken := os.Getenv("NIRMATA_API_TOKEN")

	if address == "" || apiToken == "" {
		fmt.Println("Error: NIRMATA_URL and NIRMATA_API_TOKEN environment variables must be set")
		os.Exit(1)
	}

	// Method 1: Using the convenience constructor (recommended)
	fmt.Println("Creating client with API token (Method 1)...")
	client1 := client.NewClientWithAPIKey(address, apiToken, false)

	// Method 2: Using the base constructor with auth provider
	fmt.Println("Creating client with API token (Method 2)...")
	apiAuth := client.NewAPITokenAuth(apiToken)
	client2 := client.NewClient(address, apiAuth, false)

	// Verify the clients work
	fmt.Printf("Client 1 address: %s\n", client1.Address())
	fmt.Printf("Client 2 address: %s\n", client2.Address())

	// Example: Get a collection
	fmt.Println("\nFetching environments...")
	environments, err := client1.GetCollection(client.ServiceEnvironments, "environments", nil)
	if err != nil {
		fmt.Printf("Error fetching environments: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d environment(s)\n", len(environments))
	for i, env := range environments {
		if name, ok := env["name"].(string); ok {
			fmt.Printf("  %d. %s\n", i+1, name)
		}
	}

	fmt.Println("\n✓ API token authentication successful!")
}
