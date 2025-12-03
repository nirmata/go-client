package main

import (
	"fmt"
	"os"

	"github.com/nirmata/go-client"
)

// This example demonstrates how to create a client with JWT token authentication
func main() {
	// Get configuration from environment variables
	address := os.Getenv("NIRMATA_URL")
	jwtToken := os.Getenv("NIRMATA_JWT_TOKEN")

	if address == "" || jwtToken == "" {
		fmt.Println("Error: NIRMATA_URL and NIRMATA_JWT_TOKEN environment variables must be set")
		os.Exit(1)
	}

	// Method 1: Using the convenience constructor (recommended)
	fmt.Println("Creating client with JWT token (Method 1)...")
	client1 := client.NewClientWithJWTToken(address, jwtToken, false)

	// Method 2: Using the base constructor with auth provider
	fmt.Println("Creating client with JWT token (Method 2)...")
	jwtAuth := client.NewJWTTokenAuth(jwtToken)
	client2 := client.NewClient(address, jwtAuth, false)

	// Verify the clients work
	fmt.Printf("Client 1 address: %s\n", client1.Address())
	fmt.Printf("Client 2 address: %s\n", client2.Address())

	// Example: Get a collection
	fmt.Println("\nFetching clusters...")
	clusters, err := client1.GetCollection(client.ServiceClusters, "clusters", nil)
	if err != nil {
		fmt.Printf("Error fetching clusters: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d cluster(s)\n", len(clusters))
	for i, cluster := range clusters {
		if name, ok := cluster["name"].(string); ok {
			fmt.Printf("  %d. %s\n", i+1, name)
		}
	}

	fmt.Println("\n✓ JWT token authentication successful!")
}
