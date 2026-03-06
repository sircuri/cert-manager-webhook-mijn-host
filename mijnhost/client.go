package mijnhost

import "github.com/libdns/mijnhost"

// NewClient creates a new mijn.host DNS client with the given API key.
func NewClient(apiKey string) *mijnhost.Provider {
	return &mijnhost.Provider{
		ApiKey: apiKey,
	}
}
