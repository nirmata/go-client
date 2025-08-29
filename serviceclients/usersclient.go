package serviceclients

import (
	"fmt"

	"github.com/nirmata/go-client"
)

type UsersClient struct {
	Client client.Client
}

type User struct {
	Name  string
	Email string
	Role  string
}

func New(address, apiKey string, insecure bool) *UsersClient {
	client := client.NewClient(address, apiKey, insecure)
	return &UsersClient{Client: client}
}

func (c *UsersClient) GetCurrentUser(email string) (User, error) {
	fields := []string{"name", "email", "role", "apiKey"}

	// TODO: filter by apiKey instead of email
	query := client.NewQuery().FieldEqualsValue("email", email)
	users, err := c.Client.GetCollection(client.ServiceUsers, "users", client.NewGetOptions(fields, query))
	if err != nil {
		return User{}, fmt.Errorf("failed to get current user: %w", err)
	}

	if len(users) == 0 {
		return User{}, fmt.Errorf("no users found for the current API key")
	}

	for _, user := range users {
		if user["apiKey"] == c.Client.APIKey() {
			return User{
				Name:  user["name"].(string),
				Email: user["email"].(string),
				Role:  user["role"].(string),
			}, nil
		}
	}

	return User{}, fmt.Errorf("no user found for the current API key")
}
