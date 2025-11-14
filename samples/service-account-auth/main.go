package main

import (
	"fmt"
	"os"

	"github.com/nirmata/go-client"
)

// This example demonstrates how to create a client with service account token authentication
func main() {
	// Get configuration from environment variables
	address := os.Getenv("NIRMATA_URL")
	saToken := os.Getenv("NIRMATA_SA_TOKEN")

	if address == "" || saToken == "" {
		fmt.Println("Error: NIRMATA_URL and NIRMATA_SA_TOKEN environment variables must be set")
		os.Exit(1)
	}

	// Method 1: Using the convenience constructor (recommended)
	fmt.Println("Creating client with service account token (Method 1)...")
	client1 := client.NewClientWithServiceAccountToken(address, saToken, false)

	// Method 2: Using the base constructor with auth provider
	fmt.Println("Creating client with service account token (Method 2)...")
	saAuth := client.NewServiceAccountTokenAuth(saToken)
	client2 := client.NewClient(address, saAuth, false)

	// Verify the clients work
	fmt.Printf("Client 1 address: %s\n", client1.Address())
	fmt.Printf("Client 2 address: %s\n", client2.Address())

	// Example: Get a collection
	fmt.Println("\nFetching namespaces...")
	namespaces, err := client1.GetCollection(client.ServiceEnvironments, "namespaces", nil)
	if err != nil {
		fmt.Printf("Error fetching namespaces: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d namespace(s)\n", len(namespaces))
	for i, ns := range namespaces {
		if name, ok := ns["name"].(string); ok {
			fmt.Printf("  %d. %s\n", i+1, name)
		}
	}

	fmt.Println("\n✓ Service account token authentication successful!")
	fmt.Println("\nNote: Service account authentication currently uses the same Bearer token format")
	fmt.Println("as JWT tokens. Custom logic can be added to the ServiceAccountTokenAuth implementation.")
}
