package main

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/sircuri/cert-manager-webhook-mijn-host/mijnhost"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const groupName = "acme.mijn-host.vanefferenonline.nl"

// dnsClient abstracts DNS operations for testability.
type dnsClient interface {
	AddTXTRecord(ctx context.Context, zone, name, value string, ttl int) error
	RemoveTXTRecord(ctx context.Context, zone, name, value string) error
}

// clientFactory creates a dnsClient from an API key.
type clientFactory func(apiKey string) dnsClient

// mijnHostSolver implements the webhook.Solver interface for mijn.host DNS.
// It reuses a single dnsClient per API key so that the underlying provider's
// mutex serializes concurrent read-modify-write operations on the same zone.
// This is critical because the mijn.host API uses full-zone PUT, and cert-manager
// calls Present() concurrently for wildcard + bare domain challenges.
type mijnHostSolver struct {
	kubeClient   kubernetes.Interface
	newDNSClient clientFactory

	mu      sync.Mutex
	clients map[string]dnsClient
}

func (s *mijnHostSolver) Name() string {
	return "mijn-host"
}

func (s *mijnHostSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	s.kubeClient = cl
	return nil
}

// getClient returns a shared dnsClient for the given API key. A single client
// is reused across requests so that the provider's internal mutex protects
// against concurrent read-modify-write races on the mijn.host API.
func (s *mijnHostSolver) getClient(apiKey string) dnsClient {
	if s.newDNSClient != nil {
		return s.newDNSClient(apiKey)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.clients == nil {
		s.clients = make(map[string]dnsClient)
	}
	if c, ok := s.clients[apiKey]; ok {
		return c
	}

	c := mijnhost.NewClient(apiKey)
	s.clients[apiKey] = c
	return c
}

func (s *mijnHostSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("present: %w", err)
	}

	apiKey, err := getAPIKey(s.kubeClient, ch.ResourceNamespace, cfg.APIKeySecretRef)
	if err != nil {
		return fmt.Errorf("present: %w", err)
	}

	zone := strings.TrimSuffix(ch.ResolvedZone, ".")
	fqdn := strings.TrimSuffix(ch.ResolvedFQDN, ".")

	client := s.getClient(apiKey)
	return client.AddTXTRecord(context.Background(), zone, fqdn, ch.Key, cfg.TTL)
}

func (s *mijnHostSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("cleanup: %w", err)
	}

	apiKey, err := getAPIKey(s.kubeClient, ch.ResourceNamespace, cfg.APIKeySecretRef)
	if err != nil {
		return fmt.Errorf("cleanup: %w", err)
	}

	zone := strings.TrimSuffix(ch.ResolvedZone, ".")
	fqdn := strings.TrimSuffix(ch.ResolvedFQDN, ".")

	client := s.getClient(apiKey)
	return client.RemoveTXTRecord(context.Background(), zone, fqdn, ch.Key)
}

// getAPIKey reads the API key from a Kubernetes Secret.
func getAPIKey(client kubernetes.Interface, namespace string, ref SecretRef) (string, error) {
	secret, err := client.CoreV1().Secrets(namespace).Get(context.Background(), ref.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %w", namespace, ref.Name, err)
	}

	data, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("secret %s/%s has no key %q", namespace, ref.Name, ref.Key)
	}

	return string(data), nil
}
