package mijnhost

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
	"github.com/libdns/mijnhost"
)

// defaultPropagationWait caps how long AddTXTRecord blocks waiting for the
// new value to appear at every authoritative NS. Kept under the typical
// kube-apiserver request timeout (60s) so the webhook call doesn't time out;
// cert-manager will retry Present() if propagation isn't finished yet.
const defaultPropagationWait = 50 * time.Second

// Client wraps the libdns/mijnhost Provider to expose DNS operations
// needed by the cert-manager webhook solver. A single Client instance must
// be reused across requests so that the mutex serializes concurrent
// read-modify-write operations against the mijn.host full-zone PUT API.
type Client struct {
	mu       sync.Mutex
	provider *mijnhost.Provider

	// propagator, when non-nil, is invoked after a successful write to wait
	// for the new TXT value to be visible at every authoritative NS for the
	// zone. This closes the read-after-write window of the mijn.host edge.
	propagator      Propagator
	propagationWait time.Duration
}

// NewClient creates a new mijn.host DNS client with the given API key. The
// returned client is configured to wait for DNS propagation after a write so
// that cert-manager's self-check and Let's Encrypt's validators see the new
// TXT record before the webhook reports success.
func NewClient(apiKey string) *Client {
	return &Client{
		provider: &mijnhost.Provider{
			ApiKey: apiKey,
		},
		propagator:      NewDNSPropagator(3*time.Second, 5*time.Second),
		propagationWait: defaultPropagationWait,
	}
}

// AddTXTRecord adds a TXT record to the given zone. The operation is
// serialized by the client mutex to prevent concurrent read-modify-write
// races on the mijn.host full-zone PUT API. It is idempotent: if a
// matching record already exists, no PUT is issued. After the write (or on
// the idempotent path) the call blocks until the value is visible at every
// authoritative NS for the zone, so the caller can rely on the record being
// resolvable on return.
func (c *Client) AddTXTRecord(ctx context.Context, zone string, name string, value string, ttl int) error {
	relName := toRelativeName(name, zone)

	c.mu.Lock()
	defer c.mu.Unlock()

	existing, err := c.provider.GetRecords(ctx, zone)
	if err != nil {
		return err
	}

	alreadyPresent := false
	for _, rec := range existing {
		rr := rec.RR()
		if rr.Type == "TXT" && rr.Name == relName && rr.Data == value {
			alreadyPresent = true
			break
		}
	}

	if !alreadyPresent {
		_, err = c.provider.AppendRecords(ctx, zone, []libdns.Record{
			libdns.TXT{
				Name: relName,
				TTL:  time.Duration(ttl) * time.Second,
				Text: value,
			},
		})
		if err != nil {
			return err
		}
	}

	return c.waitForPropagation(ctx, zone, name, value)
}

// RemoveTXTRecord removes a TXT record from the given zone. The operation is
// serialized by the client mutex to prevent concurrent read-modify-write
// races. It is idempotent: if the record does not exist, it returns nil.
func (c *Client) RemoveTXTRecord(ctx context.Context, zone string, name string, value string) error {
	relName := toRelativeName(name, zone)

	c.mu.Lock()
	defer c.mu.Unlock()

	existing, err := c.provider.GetRecords(ctx, zone)
	if err != nil {
		return err
	}

	var toDelete []libdns.Record
	for _, rec := range existing {
		rr := rec.RR()
		if rr.Type == "TXT" && rr.Name == relName && rr.Data == value {
			toDelete = append(toDelete, rec)
		}
	}

	if len(toDelete) == 0 {
		return nil
	}

	_, err = c.provider.DeleteRecords(ctx, zone, toDelete)
	return err
}

// waitForPropagation blocks until the propagator confirms the TXT value is
// visible at every authoritative NS, or the propagation budget expires. It
// is a no-op when no propagator is configured (used by tests).
func (c *Client) waitForPropagation(ctx context.Context, zone, fqdn, value string) error {
	if c.propagator == nil {
		return nil
	}
	wctx, cancel := context.WithTimeout(ctx, c.propagationWait)
	defer cancel()
	if err := c.propagator.WaitForTXT(wctx, zone, fqdn, value); err != nil {
		return fmt.Errorf("waiting for TXT propagation of %s: %w", fqdn, err)
	}
	return nil
}

// toRelativeName strips the zone suffix and any trailing dots from a record name
// to produce a name relative to the zone (as libdns expects).
func toRelativeName(name, zone string) string {
	// Both name and zone may have trailing dots; normalize.
	name = strings.TrimSuffix(name, ".")
	zone = strings.TrimSuffix(zone, ".")

	// Strip the zone suffix to get the relative name.
	rel := strings.TrimSuffix(name, "."+zone)
	if rel == zone {
		return "@"
	}
	return rel
}
