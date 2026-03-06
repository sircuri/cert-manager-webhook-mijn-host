package main

// Config holds the configuration for the mijn-host webhook solver.
type Config struct {
	TTL             int       `json:"ttl"`
	APIKeySecretRef SecretRef `json:"apiKeySecretRef"`
}

// SecretRef references a Kubernetes Secret.
type SecretRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}
