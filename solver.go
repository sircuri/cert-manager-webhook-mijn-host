package main

import (
	"context"
	"fmt"
	"strings"

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

// defaultClientFactory returns a factory that creates real mijn.host clients.
func defaultClientFactory() clientFactory {
	return func(apiKey string) dnsClient {
		return mijnhost.NewClient(apiKey)
	}
}

// mijnHostSolver implements the webhook.Solver interface for mijn.host DNS.
type mijnHostSolver struct {
	kubeClient    kubernetes.Interface
	newDNSClient  clientFactory
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

	client := s.getClientFactory()(apiKey)
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

	client := s.getClientFactory()(apiKey)
	return client.RemoveTXTRecord(context.Background(), zone, fqdn, ch.Key)
}

func (s *mijnHostSolver) getClientFactory() clientFactory {
	if s.newDNSClient != nil {
		return s.newDNSClient
	}
	return defaultClientFactory()
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
