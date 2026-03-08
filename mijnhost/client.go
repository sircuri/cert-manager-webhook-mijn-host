package mijnhost

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
	"github.com/libdns/mijnhost"
)

// Client wraps the libdns/mijnhost Provider to expose DNS operations
// needed by the cert-manager webhook solver. A single Client instance must
// be reused across requests so that the mutex serializes concurrent
// read-modify-write operations against the mijn.host full-zone PUT API.
type Client struct {
	mu       sync.Mutex
	provider *mijnhost.Provider
}

// NewClient creates a new mijn.host DNS client with the given API key.
func NewClient(apiKey string) *Client {
	return &Client{
		provider: &mijnhost.Provider{
			ApiKey: apiKey,
		},
	}
}

// AddTXTRecord adds a TXT record to the given zone. The operation is
// serialized by the client mutex to prevent concurrent read-modify-write
// races on the mijn.host full-zone PUT API. It is idempotent: if a
// matching record already exists, it returns nil without modification.
func (c *Client) AddTXTRecord(ctx context.Context, zone string, name string, value string, ttl int) error {
	// libdns expects the record name relative to the zone, without trailing dot.
	relName := toRelativeName(name, zone)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check for existing record to ensure idempotency. This check is inside
	// the mutex so it's atomic with the append — no TOCTOU race.
	existing, err := c.provider.GetRecords(ctx, zone)
	if err != nil {
		return err
	}
	for _, rec := range existing {
		rr := rec.RR()
		if rr.Type == "TXT" && rr.Name == relName && rr.Data == value {
			return nil
		}
	}

	_, err = c.provider.AppendRecords(ctx, zone, []libdns.Record{
		libdns.TXT{
			Name: relName,
			TTL:  time.Duration(ttl) * time.Second,
			Text: value,
		},
	})
	return err
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
