package main

import (
	"testing"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func TestLoadConfig_ValidFull(t *testing.T) {
	raw := []byte(`{"ttl":600,"apiKeySecretRef":{"name":"my-secret","key":"api-key"}}`)
	cfg, err := loadConfig(&extapi.JSON{Raw: raw})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TTL != 600 {
		t.Errorf("expected TTL 600, got %d", cfg.TTL)
	}
	if cfg.APIKeySecretRef.Name != "my-secret" {
		t.Errorf("expected name my-secret, got %s", cfg.APIKeySecretRef.Name)
	}
	if cfg.APIKeySecretRef.Key != "api-key" {
		t.Errorf("expected key api-key, got %s", cfg.APIKeySecretRef.Key)
	}
}

func TestLoadConfig_DefaultTTL(t *testing.T) {
	raw := []byte(`{"apiKeySecretRef":{"name":"my-secret","key":"api-key"}}`)
	cfg, err := loadConfig(&extapi.JSON{Raw: raw})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TTL != 300 {
		t.Errorf("expected default TTL 300, got %d", cfg.TTL)
	}
}

func TestLoadConfig_MissingName(t *testing.T) {
	raw := []byte(`{"apiKeySecretRef":{"key":"api-key"}}`)
	_, err := loadConfig(&extapi.JSON{Raw: raw})
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestLoadConfig_MissingKey(t *testing.T) {
	raw := []byte(`{"apiKeySecretRef":{"name":"my-secret"}}`)
	_, err := loadConfig(&extapi.JSON{Raw: raw})
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestLoadConfig_NilJSON(t *testing.T) {
	_, err := loadConfig(nil)
	if err == nil {
		t.Fatal("expected error for nil JSON")
	}
}

func TestLoadConfig_EmptyJSON(t *testing.T) {
	_, err := loadConfig(&extapi.JSON{Raw: []byte{}})
	if err == nil {
		t.Fatal("expected error for empty JSON")
	}
}
