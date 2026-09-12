package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/sircuri/cert-manager-webhook-mijn-host/mijnhost"
	"github.com/sircuri/cert-manager-webhook-mijn-host/zone"
)

const groupName = "acme.mijn-host.vanefferenonline.nl"

// requestTimeout bounds one Present or CleanUp. The kube-apiserver aggregator
// drops the proxied request at 60s; staying under that keeps the error
// visible to cert-manager instead of a bare timeout.
const requestTimeout = 50 * time.Second

// challengeHandler is the seam between the solver and the zone package.
type challengeHandler interface {
	Present(ctx context.Context, req zone.Request) error
	CleanUp(ctx context.Context, req zone.Request) error
	Sweep(ctx context.Context) error
}

// mijnHostSolver implements the webhook.Solver interface for mijn.host DNS.
//
// Every Present and CleanUp is a locked, reconciling read-modify-write of the
// whole zone, coordinated across all webhook pods through Kubernetes Leases
// and ConfigMaps (see the zone package). The solver itself only translates
// the cert-manager request, resolves the API key, and logs.
type mijnHostSolver struct {
	settings   Settings
	kubeClient kubernetes.Interface
	cmClient   cmclient.Interface
	handler    challengeHandler
}

func newSolver(settings Settings) *mijnHostSolver {
	return &mijnHostSolver{settings: settings}
}

func (s *mijnHostSolver) Name() string {
	return "mijn-host"
}

// Initialize builds the Kubernetes clients and the zone reconciler, then
// starts the sweep loop that removes leftovers and repairs lost records.
func (s *mijnHostSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	s.kubeClient = cl

	if s.settings.TriggerContext {
		cmc, err := cmclient.NewForConfig(kubeClientConfig)
		if err != nil {
			return fmt.Errorf("failed to create cert-manager client: %w", err)
		}
		s.cmClient = cmc
	}

	lock := zone.NewLeaseLock(cl, s.settings.Namespace, s.settings.PodName, zone.LeaseLockOptions{
		Duration:    s.settings.LockDuration,
		WaitTimeout: s.settings.LockWaitTimeout,
	})
	store := zone.NewConfigMapStore(cl, s.settings.Namespace)
	s.handler = zone.NewReconciler(lock, store,
		func(apiKey string) zone.DNSAPI { return mijnhost.NewClient(apiKey) },
		func(ctx context.Context, ref zone.SecretRef) (string, error) {
			return getAPIKey(ctx, s.kubeClient, ref)
		},
		zone.Options{
			OwnAcmeRecords: s.settings.OwnAcmeRecords,
			MaxRecordAge:   s.settings.MaxRecordAge,
			Serial:         serialReader(s.settings.SerialCheck),
			SerialRequired: s.settings.SerialCheck == serialCheckRequired,
		})

	log := logf.Log.WithName("mijn-host").WithValues("pod", s.settings.PodName)
	log.Info("solver initialised",
		"namespace", s.settings.Namespace,
		"ownAcmeRecords", s.settings.OwnAcmeRecords,
		"sweepInterval", s.settings.SweepInterval,
		"maxRecordAge", s.settings.MaxRecordAge,
		"lockWaitTimeout", s.settings.LockWaitTimeout,
		"lockDuration", s.settings.LockDuration,
		"triggerContext", s.settings.TriggerContext,
		"serialCheck", s.settings.SerialCheck)

	go s.runSweeps(logr.NewContext(context.Background(), log), stopCh)
	return nil
}

func (s *mijnHostSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	return s.handle(ch, "Present", s.handler.Present)
}

func (s *mijnHostSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	return s.handle(ch, "CleanUp", s.handler.CleanUp)
}

// handle is the shared request path: log the request, resolve config and
// trigger context, run the operation, log the outcome.
func (s *mijnHostSolver) handle(ch *v1alpha1.ChallengeRequest, action string, op func(context.Context, zone.Request) error) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	log := logf.Log.WithName("mijn-host").WithValues(
		"action", action,
		"dnsName", ch.DNSName,
		"fqdn", strings.TrimSuffix(ch.ResolvedFQDN, "."),
		"zone", strings.TrimSuffix(ch.ResolvedZone, "."),
		"namespace", ch.ResourceNamespace,
		"pod", s.settings.PodName,
	)
	log = log.WithValues(s.triggerContext(ctx, ch)...)
	ctx = logr.NewContext(ctx, log)

	start := time.Now()
	log.Info("challenge request received")
	defer func() {
		if err != nil {
			log.Error(err, "challenge request failed", "duration", time.Since(start).Round(time.Millisecond))
			return
		}
		log.Info("challenge request done", "duration", time.Since(start).Round(time.Millisecond))
	}()

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("%s: %w", strings.ToLower(action), err)
	}

	return op(ctx, zone.Request{
		Zone:         ch.ResolvedZone,
		Name:         ch.ResolvedFQDN,
		Value:        ch.Key,
		TTL:          cfg.TTL,
		ChallengeUID: string(ch.UID),
		DNSName:      ch.DNSName,
		APIKeySecretRef: zone.SecretRef{
			Namespace: ch.ResourceNamespace,
			Name:      cfg.APIKeySecretRef.Name,
			Key:       cfg.APIKeySecretRef.Key,
		},
	})
}

// triggerContext finds the Challenge, Order and Certificate behind a request
// so the logs can say which certificate caused it. Best effort: any failure
// is logged at debug level and the request proceeds without those fields.
//
// cert-manager does not fill the request's UID, so the Challenge is matched
// on DNS name plus key, which together identify one challenge.
func (s *mijnHostSolver) triggerContext(ctx context.Context, ch *v1alpha1.ChallengeRequest) []any {
	if s.cmClient == nil {
		return nil
	}
	log := logf.Log.WithName("mijn-host").V(1)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	challenges, err := s.cmClient.AcmeV1().Challenges(ch.ResourceNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Info("trigger context unavailable", "reason", err.Error())
		return nil
	}
	var fields []any
	var orderName string
	for i := range challenges.Items {
		c := &challenges.Items[i]
		if c.Spec.DNSName != ch.DNSName || c.Spec.Key != ch.Key {
			continue
		}
		fields = append(fields, "challenge", c.Name, "wildcard", c.Spec.Wildcard, "issuer", c.Spec.IssuerRef.Name)
		for _, o := range c.OwnerReferences {
			if o.Kind == "Order" {
				orderName = o.Name
			}
		}
		break
	}
	if orderName == "" {
		return fields
	}
	fields = append(fields, "order", orderName)

	order, err := s.cmClient.AcmeV1().Orders(ch.ResourceNamespace).Get(ctx, orderName, metav1.GetOptions{})
	if err != nil {
		log.Info("trigger context: order lookup failed", "order", orderName, "reason", err.Error())
		return fields
	}
	for _, o := range order.OwnerReferences {
		if o.Kind == "CertificateRequest" {
			fields = append(fields, "certificateRequest", o.Name)
		}
	}
	if cert := order.Annotations["cert-manager.io/certificate-name"]; cert != "" {
		fields = append(fields, "certificate", ch.ResourceNamespace+"/"+cert)
	}
	return fields
}

// runSweeps reconciles every known zone at startup and then periodically.
func (s *mijnHostSolver) runSweeps(ctx context.Context, stopCh <-chan struct{}) {
	log := logr.FromContextOrDiscard(ctx).WithName("sweep")
	if s.settings.SweepInterval <= 0 {
		log.Info("periodic sweep disabled")
		return
	}
	ctx = logr.NewContext(ctx, log)

	sweep := func() {
		sctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		if err := s.handler.Sweep(sctx); err != nil {
			log.Error(err, "sweep finished with errors")
		}
	}

	// Startup sweep: give the apiserver a moment so the readiness probe and
	// RBAC are settled, then clean up whatever an earlier version left behind.
	select {
	case <-stopCh:
		return
	case <-time.After(10 * time.Second):
	}
	sweep()

	ticker := time.NewTicker(s.settings.SweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			sweep()
		}
	}
}

// serialReader returns the SOA serial reader for the configured mode, or nil
// when the check is off.
func serialReader(mode string) zone.SerialReader {
	if mode == serialCheckOff {
		return nil
	}
	return zone.NewDNSSerialReader(3 * time.Second)
}

// getAPIKey reads the API key from a Kubernetes Secret.
func getAPIKey(ctx context.Context, client kubernetes.Interface, ref zone.SecretRef) (string, error) {
	secret, err := client.CoreV1().Secrets(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %w", ref.Namespace, ref.Name, err)
	}
	data, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("secret %s/%s has no key %q", ref.Namespace, ref.Name, ref.Key)
	}
	return string(data), nil
}
