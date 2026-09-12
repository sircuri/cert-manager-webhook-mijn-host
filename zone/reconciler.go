package zone

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"

	"github.com/sircuri/cert-manager-webhook-mijn-host/mijnhost"
)

// DNSAPI is the part of the mijn.host client the reconciler needs.
type DNSAPI interface {
	GetRecords(ctx context.Context, zone string) ([]mijnhost.DNSRecord, error)
	PutRecords(ctx context.Context, zone string, records []mijnhost.DNSRecord) error
}

// Request describes one challenge record to present or clean up.
type Request struct {
	Zone            string // with or without trailing dot
	Name            string // FQDN of the TXT record, with or without trailing dot
	Value           string
	TTL             int
	ChallengeUID    string
	DNSName         string
	APIKeySecretRef SecretRef
}

// Options tunes the Reconciler.
type Options struct {
	// OwnAcmeRecords makes the desired list authoritative for every
	// _acme-challenge TXT record in a zone. Default true.
	OwnAcmeRecords bool
	// MaxRecordAge drops desired records older than this on load. Default 24h.
	MaxRecordAge time.Duration
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Reconciler performs the locked read-modify-write cycle for a zone.
type Reconciler struct {
	lock   Locker
	store  Store
	newAPI func(apiKey string) DNSAPI
	apiKey func(ctx context.Context, ref SecretRef) (string, error)
	opts   Options
}

// NewReconciler wires a Reconciler. newAPI builds a mijn.host client for an
// API key; apiKey resolves a SecretRef to that key.
func NewReconciler(lock Locker, store Store, newAPI func(apiKey string) DNSAPI, apiKey func(context.Context, SecretRef) (string, error), opts Options) *Reconciler {
	if opts.MaxRecordAge <= 0 {
		opts.MaxRecordAge = 24 * time.Hour
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Reconciler{lock: lock, store: store, newAPI: newAPI, apiKey: apiKey, opts: opts}
}

// Present makes sure the record is listed as desired and present in the zone.
// A repeated Present for the same record re-checks the zone, so a record that
// an earlier stale write lost is written again.
func (r *Reconciler) Present(ctx context.Context, req Request) error {
	name := AbsoluteName(req.Name, req.Zone)
	return r.reconcile(ctx, "present", req.Zone, &req.APIKeySecretRef, func(st *State) []Key {
		for i := range st.Records {
			if st.Records[i].Name == name && st.Records[i].Value == req.Value {
				st.Records[i].TTL = req.TTL
				return nil
			}
		}
		st.Records = append(st.Records, Record{
			Name:         name,
			Value:        req.Value,
			TTL:          req.TTL,
			AddedAt:      r.opts.Now(),
			ChallengeUID: req.ChallengeUID,
			DNSName:      req.DNSName,
		})
		return nil
	})
}

// CleanUp removes the record from the desired list and from the zone.
// Removing a record that is not listed is not an error.
func (r *Reconciler) CleanUp(ctx context.Context, req Request) error {
	name := AbsoluteName(req.Name, req.Zone)
	return r.reconcile(ctx, "cleanup", req.Zone, &req.APIKeySecretRef, func(st *State) []Key {
		kept := st.Records[:0]
		for _, rec := range st.Records {
			if rec.Name == name && rec.Value == req.Value {
				continue
			}
			kept = append(kept, rec)
		}
		st.Records = kept
		return []Key{{Name: name, Value: req.Value}}
	})
}

// Sweep reconciles every zone that has state without changing the desired
// list. It removes leftovers, expired records, and repairs lost ones. Zones
// whose lock is held or whose API key cannot be read are logged and skipped.
func (r *Reconciler) Sweep(ctx context.Context) error {
	log := logr.FromContextOrDiscard(ctx)
	zones, err := r.store.ListZones(ctx)
	if err != nil {
		return err
	}
	log.Info("sweep started", "zones", zones)
	var errs []error
	for _, zone := range zones {
		if err := r.reconcile(ctx, "sweep", zone, nil, func(*State) []Key { return nil }); err != nil {
			log.Error(err, "sweep of zone failed", "zone", zone)
			errs = append(errs, fmt.Errorf("zone %s: %w", zone, err))
		}
	}
	log.Info("sweep finished", "zones", len(zones), "failed", len(errs))
	return errors.Join(errs...)
}

// reconcile is the single write path: lock, load, mutate, save, GET, compute,
// PUT if needed, unlock. secretRef is stored with the state when given and
// taken from the stored state otherwise (sweep).
func (r *Reconciler) reconcile(ctx context.Context, op, zone string, secretRef *SecretRef, mutate func(*State) []Key) error {
	zone = strings.TrimSuffix(zone, ".")
	log := logr.FromContextOrDiscard(ctx).WithValues("op", op, "zone", zone)
	ctx = logr.NewContext(ctx, log)

	release, err := r.lock.Acquire(ctx, zone)
	if err != nil {
		return err
	}
	defer release()

	h, err := r.store.Load(ctx, zone)
	if err != nil {
		return err
	}
	if secretRef != nil {
		h.State.APIKeySecretRef = *secretRef
	}
	if h.State.APIKeySecretRef.Name == "" {
		return fmt.Errorf("zone %s has no API key reference stored; it is reconciled on the next challenge", zone)
	}

	before := len(h.State.Records)
	expired := r.dropExpired(&h.State)
	remove := mutate(&h.State)
	log.Info("zone state", "records", len(h.State.Records), "before", before, "expired", len(expired), "apiKeySecret", h.State.APIKeySecretRef.String())
	if len(expired) > 0 {
		log.Info("zone state dropped records older than max age", "maxAge", r.opts.MaxRecordAge, "records", Describe(expired))
	}
	if err := r.store.Save(ctx, h); err != nil {
		return err
	}

	apiKey, err := r.apiKey(ctx, h.State.APIKeySecretRef)
	if err != nil {
		return fmt.Errorf("read API key %s: %w", h.State.APIKeySecretRef.String(), err)
	}
	api := r.newAPI(apiKey)

	current, err := api.GetRecords(ctx, zone)
	if err != nil {
		return err
	}
	payload, diff := ComputePayload(current, desiredRecords(h.State), remove, r.opts.OwnAcmeRecords)
	if !diff.Changed() {
		log.Info("zone in sync, no write needed", "challengeRecords", diff.Kept)
		return nil
	}
	log.Info("zone write", "add", Describe(diff.Add), "remove", Describe(diff.Remove), "keep", diff.Kept, "total", len(payload))
	return api.PutRecords(ctx, zone, payload)
}

func (r *Reconciler) dropExpired(st *State) []mijnhost.DNSRecord {
	cutoff := r.opts.Now().Add(-r.opts.MaxRecordAge)
	var expired []mijnhost.DNSRecord
	kept := st.Records[:0]
	for _, rec := range st.Records {
		if !rec.AddedAt.IsZero() && rec.AddedAt.Before(cutoff) {
			expired = append(expired, mijnhost.DNSRecord{Type: "TXT", Name: rec.Name, Value: rec.Value, TTL: rec.TTL})
			continue
		}
		kept = append(kept, rec)
	}
	st.Records = kept
	return expired
}

func desiredRecords(st State) []mijnhost.DNSRecord {
	out := make([]mijnhost.DNSRecord, 0, len(st.Records))
	for _, rec := range st.Records {
		out = append(out, mijnhost.DNSRecord{Type: "TXT", Name: rec.Name, Value: rec.Value, TTL: rec.TTL})
	}
	return out
}
