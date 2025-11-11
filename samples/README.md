# Go-Client Samples

This directory contains sample code demonstrating how to use the go-client library with different authentication mechanisms.

> 📋 See [STRUCTURE.md](STRUCTURE.md) for the complete directory structure and organization details.

## Samples

1. **[api-token-auth/](api-token-auth/)** - Basic API token authentication
2. **[jwt-token-auth/](jwt-token-auth/)** - JWT token authentication
3. **[service-account-auth/](service-account-auth/)** - Service account token authentication
4. **[switch-auth/](switch-auth/)** - Switching authentication at runtime
5. **[custom-auth/](custom-auth/)** - Implementing a custom authentication provider
6. **[complete-demo/](complete-demo/)** - Complete example with all authentication methods

## Running the Samples

Each sample is in its own directory with its own `main.go` file.

To run a sample:

```bash
# Set environment variables
export NIRMATA_URL="https://your-nirmata-instance.com"
export NIRMATA_API_TOKEN="your-api-token"
export NIRMATA_JWT_TOKEN="your-jwt-token"       # optional
export NIRMATA_SA_TOKEN="your-service-account-token"  # optional

# Run a specific sample (from the samples directory)
cd samples/api-token-auth && go run .
cd samples/jwt-token-auth && go run .
cd samples/service-account-auth && go run .
cd samples/switch-auth && go run .
cd samples/custom-auth && go run .
cd samples/complete-demo && go run .

# Or from the root directory
go run ./samples/api-token-auth
go run ./samples/jwt-token-auth
go run ./samples/complete-demo
```

## Prerequisites

- Go 1.16 or higher
- Access to a Nirmata instance
- Valid authentication credentials (API token, JWT token, or service account token)

## Authentication Methods

### API Token Authentication
Traditional token-based authentication using the `NIRMATA-API` header format.

### JWT Token Authentication
JSON Web Token authentication using the `Bearer` token format.

### Service Account Token Authentication
Service account token authentication (extensible for custom implementations).

## Common Patterns

### Creating a Client
```go
// With API token
client := client.NewClientWithAPIKey(address, apiToken, false)

// With JWT token
client := client.NewClientWithJWTToken(address, jwtToken, false)

// With service account token
client := client.NewClientWithServiceAccountToken(address, saToken, false)

// With custom auth provider
auth := client.NewAPITokenAuth(token)
client := client.NewClient(address, auth, false)
```

### Switching Authentication
```go
// Create client with one auth method
client := client.NewClientWithAPIKey(address, apiToken, false)

// Switch to another auth method
newAuth := client.NewJWTTokenAuth(jwtToken)
client.SetAuth(newAuth)
```

## Error Handling

All samples include proper error handling. Always check for errors when:
- Creating clients
- Making API calls
- Processing responses

## Security Notes

- Never hardcode credentials in your source code
- Use environment variables or secure configuration management
- Rotate tokens regularly
- Use the minimum required permissions

