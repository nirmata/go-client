# Quick Start Guide

## Setup

```bash
# Set your Nirmata URL
export NIRMATA_URL="https://your-nirmata-instance.com"

# Set at least one authentication token
export NIRMATA_API_TOKEN="your-api-token"
export NIRMATA_JWT_TOKEN="your-jwt-token"        # optional
export NIRMATA_SA_TOKEN="your-sa-token"          # optional
```

## Authentication Methods

### 1. API Token Authentication

```go
import "github.com/nirmata/go-client"

// Quick way
client := client.NewClientWithAPIKey(address, apiToken, false)

// Explicit way
auth := client.NewAPITokenAuth(apiToken)
client := client.NewClient(address, auth, false)
```

**Header Format:** `Authorization: NIRMATA-API {token}`

### 2. JWT Token Authentication

```go
import "github.com/nirmata/go-client"

// Quick way
client := client.NewClientWithJWTToken(address, jwtToken, false)

// Explicit way
auth := client.NewJWTTokenAuth(jwtToken)
client := client.NewClient(address, auth, false)
```

**Header Format:** `Authorization: Bearer {token}`

### 3. Service Account Token Authentication

```go
import "github.com/nirmata/go-client"

// Quick way
client := client.NewClientWithServiceAccountToken(address, saToken, false)

// Explicit way
auth := client.NewServiceAccountTokenAuth(saToken)
client := client.NewClient(address, auth, false)
```

**Header Format:** `Authorization: Bearer {token}` (extensible)

### 4. Switch Authentication at Runtime

```go
// Start with API token
client := client.NewClientWithAPIKey(address, apiToken, false)

// Switch to JWT
jwtAuth := client.NewJWTTokenAuth(jwtToken)
client.SetAuth(jwtAuth)

// Switch to Service Account
saAuth := client.NewServiceAccountTokenAuth(saToken)
client.SetAuth(saAuth)
```

## Common Operations

### Fetch a Collection

```go
// Get all environments
environments, err := client.GetCollection(
    client.ServiceEnvironments,
    "environments",
    nil,
)
if err != nil {
    // handle error
}
```

### Fetch with Options

```go
// Create query
query := client.NewQuery().FieldEqualsValue("name", "production")

// Create options
opts := client.NewGetOptions(
    []string{"name", "id", "description"},
    query,
)

// Fetch with options
items, err := client.GetCollection(
    client.ServiceEnvironments,
    "environments",
    opts,
)
```

### Get Single Object

```go
// Parse an ID
id, err := client.ParseID(idString)
if err != nil {
    // handle error
}

// Get the object
obj, err := client.Get(id, nil)
if err != nil {
    // handle error
}
```

## Run Samples

```bash
# Run individual samples (from root directory)
go run ./samples/api-token-auth
go run ./samples/jwt-token-auth
go run ./samples/service-account-auth
go run ./samples/switch-auth
go run ./samples/custom-auth

# Run comprehensive example
go run ./samples/complete-demo

# Or navigate to a sample directory and run
cd samples/api-token-auth && go run .
```

## Custom Authentication

Implement the `AuthProvider` interface:

```go
type CustomAuth struct {
    token string
}

func (a *CustomAuth) SetAuthHeader(req *http.Request) client.Error {
    req.Header.Add("Authorization", "Custom " + a.token)
    // Add any custom logic here
    return nil
}

// Use it
auth := &CustomAuth{token: "my-token"}
client := client.NewClient(address, auth, false)
```

## Best Practices

1. **Never hardcode tokens** - Use environment variables or secure storage
2. **Choose the right auth method** - API tokens for services, JWT for users
3. **Handle errors properly** - Always check for authentication errors
4. **Rotate tokens regularly** - Implement token refresh for long-running apps
5. **Use HTTPS in production** - Set `insecure` parameter to `false`

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "No auth provider configured" | Create client with an AuthProvider |
| 401 Unauthorized | Verify token is valid and has correct permissions |
| Connection refused | Check NIRMATA_URL is correct and accessible |
| Token expired | Refresh token and call `SetAuth()` with new token |

## Next Steps

- Review [README.md](README.md) for detailed examples
- See [custom-auth/main.go](custom-auth/main.go) for advanced authentication patterns
- Check the main [go-client documentation](../README.md) for full API reference

