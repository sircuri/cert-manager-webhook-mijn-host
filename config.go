package main

import (
	"encoding/json"
	"fmt"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

const defaultTTL = 300

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

// loadConfig unmarshals the JSON configuration from a cert-manager ChallengeRequest
// and applies defaults.
func loadConfig(cfgJSON *extapi.JSON) (Config, error) {
	var cfg Config

	if cfgJSON == nil || len(cfgJSON.Raw) == 0 {
		return cfg, fmt.Errorf("no solver config provided")
	}

	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("failed to unmarshal solver config: %w", err)
	}

	if cfg.TTL == 0 {
		cfg.TTL = defaultTTL
	}

	if cfg.APIKeySecretRef.Name == "" {
		return cfg, fmt.Errorf("apiKeySecretRef.name is required")
	}
	if cfg.APIKeySecretRef.Key == "" {
		return cfg, fmt.Errorf("apiKeySecretRef.key is required")
	}

	return cfg, nil
}
