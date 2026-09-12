package main

import (
	"context"
	"errors"
	"testing"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmfake "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/sircuri/cert-manager-webhook-mijn-host/zone"
)

// fakeHandler records reconciler calls and can simulate errors.
type fakeHandler struct {
	presents   []zone.Request
	cleanups   []zone.Request
	sweeps     int
	presentErr error
	cleanupErr error
}

func (f *fakeHandler) Present(_ context.Context, req zone.Request) error {
	f.presents = append(f.presents, req)
	return f.presentErr
}

func (f *fakeHandler) CleanUp(_ context.Context, req zone.Request) error {
	f.cleanups = append(f.cleanups, req)
	return f.cleanupErr
}

func (f *fakeHandler) Sweep(context.Context) error {
	f.sweeps++
	return nil
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

func newTestSolver(fh *fakeHandler) *mijnHostSolver {
	return &mijnHostSolver{
		settings:   Settings{PodName: "pod-test", Namespace: "cert-manager"},
		kubeClient: fake.NewClientset(),
		handler:    fh,
	}
}

func challengeRequest(zoneName, fqdn, key string, config *extapi.JSON) *v1alpha1.ChallengeRequest {
	return &v1alpha1.ChallengeRequest{
		UID:               types.UID("uid-1"),
		Action:            v1alpha1.ChallengeActionPresent,
		Type:              "dns-01",
		DNSName:           "example.com",
		ResolvedZone:      zoneName,
		ResolvedFQDN:      fqdn,
		Key:               key,
		ResourceNamespace: "default",
		Config:            config,
	}
}

func TestPresent_TranslatesRequest(t *testing.T) {
	fh := &fakeHandler{}
	solver := newTestSolver(fh)

	ch := challengeRequest("example.com.", "_acme-challenge.example.com.", "token123", validConfig())
	if err := solver.Present(ch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fh.presents) != 1 {
		t.Fatalf("expected 1 Present call, got %d", len(fh.presents))
	}
	got := fh.presents[0]
	want := zone.Request{
		Zone:            "example.com.",
		Name:            "_acme-challenge.example.com.",
		Value:           "token123",
		TTL:             600,
		ChallengeUID:    "uid-1",
		DNSName:         "example.com",
		APIKeySecretRef: zone.SecretRef{Namespace: "default", Name: "my-secret", Key: "api-key"},
	}
	if got != want {
		t.Errorf("request = %+v, want %+v", got, want)
	}
}

func TestCleanUp_TranslatesRequest(t *testing.T) {
	fh := &fakeHandler{}
	solver := newTestSolver(fh)

	ch := challengeRequest("example.com.", "_acme-challenge.example.com.", "specific-token", validConfig())
	if err := solver.CleanUp(ch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fh.cleanups) != 1 || len(fh.presents) != 0 {
		t.Fatalf("expected 1 CleanUp call, got presents=%d cleanups=%d", len(fh.presents), len(fh.cleanups))
	}
	if fh.cleanups[0].Value != "specific-token" || fh.cleanups[0].Zone != "example.com." {
		t.Errorf("request = %+v", fh.cleanups[0])
	}
}

func TestPresent_DefaultTTL(t *testing.T) {
	fh := &fakeHandler{}
	solver := newTestSolver(fh)

	ch := challengeRequest("example.com.", "_acme-challenge.example.com.", "token", configWithoutTTL())
	if err := solver.Present(ch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fh.presents[0].TTL != 300 {
		t.Errorf("expected default TTL 300, got %d", fh.presents[0].TTL)
	}
}

func TestPresent_HandlerErrorPropagates(t *testing.T) {
	apiErr := errors.New("zone example.com is locked")
	solver := newTestSolver(&fakeHandler{presentErr: apiErr})

	err := solver.Present(challengeRequest("example.com.", "_acme-challenge.example.com.", "token", validConfig()))
	if !errors.Is(err, apiErr) {
		t.Fatalf("expected handler error to propagate, got: %v", err)
	}
}

func TestCleanUp_HandlerErrorPropagates(t *testing.T) {
	apiErr := errors.New("API timeout")
	solver := newTestSolver(&fakeHandler{cleanupErr: apiErr})

	err := solver.CleanUp(challengeRequest("example.com.", "_acme-challenge.example.com.", "token", validConfig()))
	if !errors.Is(err, apiErr) {
		t.Fatalf("expected handler error to propagate, got: %v", err)
	}
}

func TestPresent_InvalidConfigDoesNotReachHandler(t *testing.T) {
	fh := &fakeHandler{}
	solver := newTestSolver(fh)

	if err := solver.Present(challengeRequest("example.com.", "_acme-challenge.example.com.", "token", nil)); err == nil {
		t.Fatal("expected error for nil config")
	}
	if len(fh.presents) != 0 {
		t.Fatal("handler must not be called with invalid config")
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

func TestGetAPIKey(t *testing.T) {
	kube := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "my-secret", Namespace: "default"},
		Data:       map[string][]byte{"api-key": []byte("s3cret")},
	})
	ref := zone.SecretRef{Namespace: "default", Name: "my-secret", Key: "api-key"}

	key, err := getAPIKey(context.Background(), kube, ref)
	if err != nil || key != "s3cret" {
		t.Fatalf("got %q, %v", key, err)
	}
	if _, err := getAPIKey(context.Background(), kube, zone.SecretRef{Namespace: "default", Name: "my-secret", Key: "missing"}); err == nil {
		t.Fatal("expected error for missing key")
	}
	if _, err := getAPIKey(context.Background(), kube, zone.SecretRef{Namespace: "other", Name: "my-secret", Key: "api-key"}); err == nil {
		t.Fatal("expected error for missing secret")
	}
}

func TestTriggerContext_ResolvesCertificate(t *testing.T) {
	order := &cmacme.Order{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "wildcard-example-1-123",
			Namespace: "default",
			Annotations: map[string]string{
				"cert-manager.io/certificate-name": "wildcard-example",
			},
			OwnerReferences: []metav1.OwnerReference{{Kind: "CertificateRequest", Name: "wildcard-example-1"}},
		},
	}
	challenge := &cmacme.Challenge{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "wildcard-example-1-123-456",
			Namespace:       "default",
			UID:             types.UID("uid-1"),
			OwnerReferences: []metav1.OwnerReference{{Kind: "Order", Name: order.Name}},
		},
		Spec: cmacme.ChallengeSpec{Wildcard: true, IssuerRef: cmmeta.IssuerReference{Name: "letsencrypt-prod"}},
	}
	solver := newTestSolver(&fakeHandler{})
	solver.cmClient = cmfake.NewSimpleClientset(order, challenge)

	fields := solver.triggerContext(context.Background(), challengeRequest("example.com.", "_acme-challenge.example.com.", "k", validConfig()))
	got := map[string]any{}
	for i := 0; i+1 < len(fields); i += 2 {
		got[fields[i].(string)] = fields[i+1]
	}
	if got["certificate"] != "default/wildcard-example" || got["order"] != order.Name || got["challenge"] != challenge.Name || got["wildcard"] != true || got["issuer"] != "letsencrypt-prod" {
		t.Fatalf("fields = %v", got)
	}
}

func TestTriggerContext_UnknownChallengeYieldsNothing(t *testing.T) {
	solver := newTestSolver(&fakeHandler{})
	solver.cmClient = cmfake.NewSimpleClientset()

	if fields := solver.triggerContext(context.Background(), challengeRequest("example.com.", "_acme-challenge.example.com.", "k", validConfig())); len(fields) != 0 {
		t.Fatalf("expected no fields, got %v", fields)
	}
}

func TestTriggerContext_DisabledWithoutClient(t *testing.T) {
	solver := newTestSolver(&fakeHandler{})
	if fields := solver.triggerContext(context.Background(), challengeRequest("example.com.", "_acme-challenge.example.com.", "k", validConfig())); fields != nil {
		t.Fatalf("expected nil, got %v", fields)
	}
}
