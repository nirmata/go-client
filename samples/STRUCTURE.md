# Samples Directory Structure

```
samples/
├── README.md                          # Main documentation
├── QUICKSTART.md                      # Quick reference guide  
├── STRUCTURE.md                       # This file
├── .gitignore                         # Git ignore rules
│
├── api-token-auth/                    # API Token Authentication
│   └── main.go                        # Standalone example
│
├── jwt-token-auth/                    # JWT Token Authentication
│   └── main.go                        # Standalone example
│
├── service-account-auth/              # Service Account Token Authentication
│   └── main.go                        # Standalone example
│
├── switch-auth/                       # Runtime Auth Switching
│   └── main.go                        # Demonstrates SetAuth()
│
├── custom-auth/                       # Custom Auth Provider
│   └── main.go                        # Advanced patterns
│
└── complete-demo/                     # Comprehensive Demo
    └── main.go                        # All auth methods in one
```

## Design

Each sample is a standalone Go program in its own directory:
- **Self-contained**: Each has its own `main.go` with a complete example
- **Independent**: Can be run without affecting other samples
- **No conflicts**: Separate directories prevent `main()` declaration conflicts

## Running

```bash
# From project root
go run ./samples/api-token-auth
go run ./samples/jwt-token-auth
go run ./samples/complete-demo

# From within a sample directory
cd samples/api-token-auth
go run .
```

## Building

```bash
# Build all samples at once (from project root)
go build ./samples/...

# Build a specific sample
go build ./samples/api-token-auth
```

## Adding New Samples

To add a new sample:

1. Create a new directory: `mkdir samples/my-new-sample`
2. Create `main.go` inside: `touch samples/my-new-sample/main.go`
3. Write your sample with `package main` and `func main()`
4. Update the README.md to list the new sample
5. Test: `go run ./samples/my-new-sample`

