package main

import (
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"k8s.io/client-go/rest"
)

// solver implements the webhook.Solver interface.
type solver struct{}

func (s *solver) Name() string {
	return "mijn-host"
}

func (s *solver) Present(ch *v1alpha1.ChallengeRequest) error {
	return nil
}

func (s *solver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	return nil
}

func (s *solver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	return nil
}
