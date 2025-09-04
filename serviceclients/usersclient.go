package serviceclients

import (
	"fmt"
	"net/url"

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
	fields := []string{"name", "email", "role", "id", "parent"}

	urlEncodedAPIKey := url.QueryEscape(c.Client.APIKey())

	query := client.NewQuery().FieldEqualsValue("apiKey", urlEncodedAPIKey)
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

	var name, email, role, id, tenantID string
	if IName, exists := user["name"]; exists {
		name = IName.(string)
	}
	if IEmail, exists := user["email"]; exists {
		email = IEmail.(string)
	}
	if IRole, exists := user["role"]; exists {
		role = IRole.(string)
	}
	if IID, exists := user["id"]; exists {
		id = IID.(string)
	}

	if IParent, exists := user["parent"]; exists {
		parent := IParent.(map[string]interface{})
		if ITenantID, exists := parent["id"]; exists {
			tenantID = ITenantID.(string)
		}
	}

	return User{
		Name:     name,
		Email:    email,
		Role:     role,
		ID:       id,
		TenantID: tenantID,
	}, nil
}
