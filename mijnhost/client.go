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

// defaultVisibilityWait caps how long AddTXTRecord blocks waiting for the
// mijn.host API's read view to catch up with a write we just performed.
// Kept well under the typical kube-apiserver request timeout so the webhook
// call itself does not time out.
const defaultVisibilityWait = 30 * time.Second

// defaultVisibilityPoll is the interval between GetRecords retries while
// waiting for the API to reflect the just-written record.
const defaultVisibilityPoll = 1500 * time.Millisecond

// Client wraps the libdns/mijnhost Provider to expose DNS operations needed
// by the cert-manager webhook solver. A single Client instance must be reused
// across requests so that the mutex serializes concurrent read-modify-write
// operations against the mijn.host full-zone PUT API.
type Client struct {
	mu       sync.Mutex
	provider *mijnhost.Provider

	// visibilityWait caps how long AddTXTRecord blocks after a successful
	// AppendRecords waiting for the mijn.host API to return the new record
	// on a follow-up GetRecords. Closes the read-after-write window of the
	// mijn.host backend so the next Present (e.g. the second challenge of a
	// wildcard order) sees the first challenge's record and appends to it
	// instead of overwriting it via the full-zone PUT.
	//
	// Zero disables the wait (used by tests with a strongly-consistent mock).
	visibilityWait time.Duration
	visibilityPoll time.Duration
}

// NewClient creates a new mijn.host DNS client with the given API key.
func NewClient(apiKey string) *Client {
	return &Client{
		provider: &mijnhost.Provider{
			ApiKey: apiKey,
		},
		visibilityWait: defaultVisibilityWait,
		visibilityPoll: defaultVisibilityPoll,
	}
}

// AddTXTRecord adds a TXT record to the given zone. The operation is
// serialized by the client mutex to prevent concurrent read-modify-write
// races on the mijn.host full-zone PUT API. It is idempotent: if a matching
// record already exists, no PUT is issued. After a write, the call blocks
// (still under the mutex) until the API reflects the new record, so any
// subsequent caller observes the up-to-date zone state.
func (c *Client) AddTXTRecord(ctx context.Context, zone string, name string, value string, ttl int) error {
	relName := toRelativeName(name, zone)

	c.mu.Lock()
	defer c.mu.Unlock()

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
	if err != nil {
		return err
	}

	return c.waitForVisibility(ctx, zone, relName, value)
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

// waitForVisibility polls provider.GetRecords until the (relName, value) TXT
// record appears in the API response, or visibilityWait elapses. This
// guarantees that the next caller's Get-Modify-PUT (libdns AppendRecords)
// sees the record we just wrote, so it appends to it instead of clobbering it.
func (c *Client) waitForVisibility(ctx context.Context, zone, relName, value string) error {
	if c.visibilityWait <= 0 {
		return nil
	}

	deadline := time.Now().Add(c.visibilityWait)
	var lastErr error

	for {
		recs, err := c.provider.GetRecords(ctx, zone)
		if err == nil {
			for _, rec := range recs {
				rr := rec.RR()
				if rr.Type == "TXT" && rr.Name == relName && rr.Data == value {
					return nil
				}
			}
		} else {
			lastErr = err
		}

		if time.Now().After(deadline) {
			if lastErr != nil {
				return fmt.Errorf("API visibility timeout for %s after %s (last GetRecords error: %w)",
					relName, c.visibilityWait, lastErr)
			}
			return fmt.Errorf("API visibility timeout: %s value not visible after %s", relName, c.visibilityWait)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.visibilityPoll):
		}
	}
}

// toRelativeName strips the zone suffix and any trailing dots from a record name
// to produce a name relative to the zone (as libdns expects).
func toRelativeName(name, zone string) string {
	name = strings.TrimSuffix(name, ".")
	zone = strings.TrimSuffix(zone, ".")

	rel := strings.TrimSuffix(name, "."+zone)
	if rel == zone {
		return "@"
	}
	return rel
}
