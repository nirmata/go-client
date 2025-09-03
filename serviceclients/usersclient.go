package serviceclients

import (
	"fmt"

	"github.com/nirmata/go-client"
)

type UsersClient struct {
	Client client.Client
}

type User struct {
	Name     string
	Email    string
	Role     string
	ID       string
	TenantID string
}

func New(address, apiKey string, insecure bool) *UsersClient {
	client := client.NewClient(address, apiKey, insecure)
	return &UsersClient{Client: client}
}

func (c *UsersClient) GetCurrentUser() (User, error) {
	fields := []string{"name", "email", "role", "id", "tenantId"}

	query := client.NewQuery().FieldEqualsValue("apiKey", c.Client.APIKey())
	users, err := c.Client.GetCollection(client.ServiceUsers, "users", client.NewGetOptions(fields, query))
	if err != nil {
		return User{}, fmt.Errorf("failed to get current user: %w", err)
	}

	if len(users) == 0 {
		return User{}, fmt.Errorf("no users found for the current API key")
	}

	if len(users) > 1 {
		return User{}, fmt.Errorf("multiple users found for the current API key")
	}
	user := users[0]
	return User{
		Name:     user["name"].(string),
		Email:    user["email"].(string),
		Role:     user["role"].(string),
		ID:       user["id"].(string),
		TenantID: user["tenantId"].(string),
	}, nil
}
