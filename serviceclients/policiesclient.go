package serviceclients

import (
	"encoding/json"
	"fmt"

	"github.com/nirmata/go-client"
)

type GithubAppAccessToken struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

type PoliciesClient struct {
	Client client.Client
}

func NewPoliciesClient(address string, auth client.AuthProvider, insecure bool) *PoliciesClient {
	return &PoliciesClient{Client: client.NewClient(address, auth, insecure)}
}

func (c *PoliciesClient) GetGithubAppAccessToken(installationOwner string) (*GithubAppAccessToken, error) {
	res, _, reqErr := c.Client.GetURL(client.ServicePolicies, "github/accessToken/"+installationOwner)
	if reqErr != nil {
		return nil, fmt.Errorf("failed to get github app access token: %w", reqErr)
	}

	var githubAppAccessToken GithubAppAccessToken
	err := json.Unmarshal(res, &githubAppAccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal github app access token: %w", err)
	}
	return &githubAppAccessToken, nil
}
