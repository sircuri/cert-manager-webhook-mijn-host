package zone

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	managedByLabel = "app.kubernetes.io/managed-by"
	managedByValue = "mijn-host-webhook"
	zoneLabel      = "mijn-host.vanefferenonline.nl/zone"
	zoneAnnotation = "mijn-host.vanefferenonline.nl/zone-name"
	stateKey       = "state"
)

// SecretRef points at the Kubernetes Secret holding the mijn.host API key
// for a zone. Stored with the zone state so the sweep can find the key
// without a challenge request.
type SecretRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Key       string `json:"key"`
}

func (r SecretRef) String() string { return r.Namespace + "/" + r.Name + "[" + r.Key + "]" }

// Record is one challenge TXT record the webhook wants present in a zone.
type Record struct {
	Name         string    `json:"name"` // absolute, with trailing dot
	Value        string    `json:"value"`
	TTL          int       `json:"ttl"`
	AddedAt      time.Time `json:"addedAt"`
	ChallengeUID string    `json:"challengeUID,omitempty"`
	DNSName      string    `json:"dnsName,omitempty"`
}

// State is the durable per-zone desired state.
type State struct {
	Zone            string    `json:"zone"`
	APIKeySecretRef SecretRef `json:"apiKeySecretRef"`
	Records         []Record  `json:"records"`
}

// Handle is a loaded State plus what is needed to save it back with
// optimistic concurrency.
type Handle struct {
	State           State
	resourceVersion string
	exists          bool
}

// Exists reports whether the ConfigMap existed when the state was loaded.
func (h *Handle) Exists() bool { return h.exists }

// Store persists State in one ConfigMap per zone.
type Store interface {
	Load(ctx context.Context, zone string) (*Handle, error)
	Save(ctx context.Context, h *Handle) error
	ListZones(ctx context.Context) ([]string, error)
}

// ConfigMapStore implements Store on Kubernetes ConfigMaps in one namespace.
type ConfigMapStore struct {
	client    kubernetes.Interface
	namespace string
}

// NewConfigMapStore creates a store in the given namespace.
func NewConfigMapStore(client kubernetes.Interface, namespace string) *ConfigMapStore {
	return &ConfigMapStore{client: client, namespace: namespace}
}

// Load reads the state for zone. A missing ConfigMap yields an empty state
// whose Save creates the ConfigMap.
func (s *ConfigMapStore) Load(ctx context.Context, zone string) (*Handle, error) {
	zone = strings.TrimSuffix(zone, ".")
	cm, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(ctx, ObjectName(zone), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return &Handle{State: State{Zone: zone}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load state for zone %s: %w", zone, err)
	}
	h := &Handle{resourceVersion: cm.ResourceVersion, exists: true}
	if raw := cm.Data[stateKey]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &h.State); err != nil {
			return nil, fmt.Errorf("decode state for zone %s in configmap %s: %w", zone, cm.Name, err)
		}
	}
	h.State.Zone = zone
	return h, nil
}

// Save writes the state back. It fails with a conflict if the ConfigMap
// changed since Load, which can only happen if a write escaped the zone lock.
func (s *ConfigMapStore) Save(ctx context.Context, h *Handle) error {
	raw, err := json.Marshal(h.State)
	if err != nil {
		return err
	}
	name := ObjectName(h.State.Zone)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: s.namespace,
			Labels: map[string]string{
				managedByLabel: managedByValue,
				zoneLabel:      strings.TrimPrefix(name, "mijn-host-zone-"),
			},
			Annotations:     map[string]string{zoneAnnotation: h.State.Zone},
			ResourceVersion: h.resourceVersion,
		},
		Data: map[string]string{stateKey: string(raw)},
	}

	cms := s.client.CoreV1().ConfigMaps(s.namespace)
	var saved *corev1.ConfigMap
	if h.exists {
		saved, err = cms.Update(ctx, cm, metav1.UpdateOptions{})
	} else {
		saved, err = cms.Create(ctx, cm, metav1.CreateOptions{})
	}
	if err != nil {
		return fmt.Errorf("save state for zone %s: %w", h.State.Zone, err)
	}
	h.resourceVersion = saved.ResourceVersion
	h.exists = true
	return nil
}

// ListZones returns every zone that has state, from the ConfigMap labels.
func (s *ConfigMapStore) ListZones(ctx context.Context) ([]string, error) {
	list, err := s.client.CoreV1().ConfigMaps(s.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: managedByLabel + "=" + managedByValue + "," + zoneLabel,
	})
	if err != nil {
		return nil, fmt.Errorf("list zone state: %w", err)
	}
	zones := make([]string, 0, len(list.Items))
	for _, cm := range list.Items {
		if z := cm.Annotations[zoneAnnotation]; z != "" {
			zones = append(zones, z)
		}
	}
	return zones, nil
}
