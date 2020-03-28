package nirmataerr

import "github.com/nirmata/go-client/pkg/client"

var (
	// ErrMissingToken is an error that is returned if token configuration is
	// not found.
	ErrMissingToken = client.NewError("ErrMissingToken", "could not find token configuration", nil)
)
