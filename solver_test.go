package main

import (
	"context"
	"errors"
	"testing"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// fakeDNSClient records calls and can simulate errors.
type fakeDNSClient struct {
	addCalls    []addCall
	removeCalls []removeCall
	addErr      error
	removeErr   error
}

type addCall struct {
	zone, name, value string
	ttl               int
}

type removeCall struct {
	zone, name, value string
}

func (f *fakeDNSClient) AddTXTRecord(_ context.Context, zone, name, value string, ttl int) error {
	f.addCalls = append(f.addCalls, addCall{zone, name, value, ttl})
	return f.addErr
}

func (f *fakeDNSClient) RemoveTXTRecord(_ context.Context, zone, name, value string) error {
	f.removeCalls = append(f.removeCalls, removeCall{zone, name, value})
	return f.removeErr
}

func validConfig() *extapi.JSON {
	return &extapi.JSON{
		Raw: []byte(`{"ttl":600,"apiKeySecretRef":{"name":"my-secret","key":"api-key"}}`),
	}
}

func configWithoutTTL() *extapi.JSON {
	return &extapi.JSON{
		Raw: []byte(`{"apiKeySecretRef":{"name":"my-secret","key":"api-key"}}`),
	}
}

func fakeSecret(namespace, name, key, value string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			key: []byte(value),
		},
	}
}

func newTestSolver(fc *fakeDNSClient, secrets ...*corev1.Secret) *mijnHostSolver {
	fakeClient := fake.NewSimpleClientset()
	for _, s := range secrets {
		fakeClient.CoreV1().Secrets(s.Namespace).Create(context.Background(), s.DeepCopy(), metav1.CreateOptions{})
	}

	return &mijnHostSolver{
		kubeClient: fakeClient,
		newDNSClient: func(apiKey string) dnsClient {
			return fc
		},
	}
}

func challengeRequest(zone, fqdn, key string, config *extapi.JSON) *v1alpha1.ChallengeRequest {
	return &v1alpha1.ChallengeRequest{
		ResolvedZone:      zone,
		ResolvedFQDN:      fqdn,
		Key:               key,
		ResourceNamespace: "default",
		Config:            config,
	}
}

func TestPresent_ConstructsTXTRecordName(t *testing.T) {
	fc := &fakeDNSClient{}
	solver := newTestSolver(fc, fakeSecret("default", "my-secret", "api-key", "test-key"))

	ch := challengeRequest("example.com.", "_acme-challenge.example.com.", "token123", validConfig())
	if err := solver.Present(ch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fc.addCalls) != 1 {
		t.Fatalf("expected 1 AddTXTRecord call, got %d", len(fc.addCalls))
	}

	call := fc.addCalls[0]
	if call.zone != "example.com" {
		t.Errorf("expected zone 'example.com', got %q", call.zone)
	}
	if call.name != "_acme-challenge.example.com" {
		t.Errorf("expected name '_acme-challenge.example.com', got %q", call.name)
	}
	if call.value != "token123" {
		t.Errorf("expected value 'token123', got %q", call.value)
	}
	if call.ttl != 600 {
		t.Errorf("expected TTL 600, got %d", call.ttl)
	}
}

func TestPresent_HandlesTrailingDot(t *testing.T) {
	fc := &fakeDNSClient{}
	solver := newTestSolver(fc, fakeSecret("default", "my-secret", "api-key", "test-key"))

	ch := challengeRequest("example.com.", "_acme-challenge.example.com.", "token", validConfig())
	if err := solver.Present(ch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	call := fc.addCalls[0]
	// Trailing dots should be stripped
	if call.zone != "example.com" {
		t.Errorf("zone should not have trailing dot, got %q", call.zone)
	}
	if call.name != "_acme-challenge.example.com" {
		t.Errorf("name should not have trailing dot, got %q", call.name)
	}
}

func TestPresent_Idempotent(t *testing.T) {
	fc := &fakeDNSClient{}
	solver := newTestSolver(fc, fakeSecret("default", "my-secret", "api-key", "test-key"))

	ch := challengeRequest("example.com.", "_acme-challenge.example.com.", "token", validConfig())

	if err := solver.Present(ch); err != nil {
		t.Fatalf("first Present: %v", err)
	}
	if err := solver.Present(ch); err != nil {
		t.Fatalf("second Present: %v", err)
	}

	if len(fc.addCalls) != 2 {
		t.Fatalf("expected 2 AddTXTRecord calls, got %d", len(fc.addCalls))
	}
}

func TestCleanUp_RemovesOnlyMatchingRecord(t *testing.T) {
	fc := &fakeDNSClient{}
	solver := newTestSolver(fc, fakeSecret("default", "my-secret", "api-key", "test-key"))

	ch := challengeRequest("example.com.", "_acme-challenge.example.com.", "specific-token", validConfig())
	if err := solver.CleanUp(ch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fc.removeCalls) != 1 {
		t.Fatalf("expected 1 RemoveTXTRecord call, got %d", len(fc.removeCalls))
	}

	call := fc.removeCalls[0]
	if call.zone != "example.com" {
		t.Errorf("expected zone 'example.com', got %q", call.zone)
	}
	if call.name != "_acme-challenge.example.com" {
		t.Errorf("expected name '_acme-challenge.example.com', got %q", call.name)
	}
	if call.value != "specific-token" {
		t.Errorf("expected value 'specific-token', got %q", call.value)
	}
}

func TestCleanUp_NoErrorWhenRecordAbsent(t *testing.T) {
	fc := &fakeDNSClient{} // removeErr is nil, simulating no-op
	solver := newTestSolver(fc, fakeSecret("default", "my-secret", "api-key", "test-key"))

	ch := challengeRequest("example.com.", "_acme-challenge.example.com.", "nonexistent", validConfig())
	if err := solver.CleanUp(ch); err != nil {
		t.Fatalf("expected no error for absent record, got: %v", err)
	}
}

func TestLoadConfig_DefaultTTL_Solver(t *testing.T) {
	fc := &fakeDNSClient{}
	solver := newTestSolver(fc, fakeSecret("default", "my-secret", "api-key", "test-key"))

	ch := challengeRequest("example.com.", "_acme-challenge.example.com.", "token", configWithoutTTL())
	if err := solver.Present(ch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if fc.addCalls[0].ttl != 300 {
		t.Errorf("expected default TTL 300, got %d", fc.addCalls[0].ttl)
	}
}

func TestLoadConfig_MissingSecretRef(t *testing.T) {
	raw := &extapi.JSON{Raw: []byte(`{"ttl":600}`)}
	_, err := loadConfig(raw)
	if err == nil {
		t.Fatal("expected error for missing secretRef")
	}
	if got := err.Error(); got != "apiKeySecretRef.name is required" {
		t.Errorf("unexpected error message: %s", got)
	}
}

func TestPresent_APIErrorPropagates(t *testing.T) {
	apiErr := errors.New("API rate limit exceeded")
	fc := &fakeDNSClient{addErr: apiErr}
	solver := newTestSolver(fc, fakeSecret("default", "my-secret", "api-key", "test-key"))

	ch := challengeRequest("example.com.", "_acme-challenge.example.com.", "token", validConfig())
	err := solver.Present(ch)
	if err == nil {
		t.Fatal("expected error from API failure")
	}
	if !errors.Is(err, apiErr) {
		t.Errorf("expected API error to propagate, got: %v", err)
	}
}

func TestCleanUp_APIErrorPropagates(t *testing.T) {
	apiErr := errors.New("API timeout")
	fc := &fakeDNSClient{removeErr: apiErr}
	solver := newTestSolver(fc, fakeSecret("default", "my-secret", "api-key", "test-key"))

	ch := challengeRequest("example.com.", "_acme-challenge.example.com.", "token", validConfig())
	err := solver.CleanUp(ch)
	if err == nil {
		t.Fatal("expected error from API failure")
	}
	if !errors.Is(err, apiErr) {
		t.Errorf("expected API error to propagate, got: %v", err)
	}
}

func TestPresent_MissingSecret(t *testing.T) {
	fc := &fakeDNSClient{}
	// No secret created — solver should fail to get API key
	solver := newTestSolver(fc)

	ch := challengeRequest("example.com.", "_acme-challenge.example.com.", "token", validConfig())
	err := solver.Present(ch)
	if err == nil {
		t.Fatal("expected error when secret is missing")
	}
}

func TestCleanUp_MissingSecret(t *testing.T) {
	fc := &fakeDNSClient{}
	solver := newTestSolver(fc)

	ch := challengeRequest("example.com.", "_acme-challenge.example.com.", "token", validConfig())
	err := solver.CleanUp(ch)
	if err == nil {
		t.Fatal("expected error when secret is missing")
	}
}

func TestPresent_InvalidConfig(t *testing.T) {
	fc := &fakeDNSClient{}
	solver := newTestSolver(fc, fakeSecret("default", "my-secret", "api-key", "test-key"))

	ch := challengeRequest("example.com.", "_acme-challenge.example.com.", "token", nil)
	err := solver.Present(ch)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}
