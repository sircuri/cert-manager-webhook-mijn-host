package mijnhost

import (
	"context"
	"strings"
	"sync"
)

// txtKey identifies a TXT record in our cache. Multiple values can coexist
// at the same name, which is required for wildcard certs (apex + wildcard
// challenges share _acme-challenge.<zone>).
type txtKey struct {
	name  string // absolute, with trailing dot, as the API stores it
	value string
}

// recordID is the dedup key when merging records (type+name+value).
type recordID struct {
	Type, Name, Value string
}

// Client manages TXT records on mijn.host zones for cert-manager DNS-01
// challenges.
//
// The mijn.host API is full-zone PUT and read-after-write inconsistent:
// a GET shortly after a PUT can return the pre-write zone state, even
// from the same caller. The libdns/mijnhost provider's Get-Modify-PUT
// helpers turn that into a real race for wildcard certs, where apex
// and wildcard challenges write to the same _acme-challenge.<zone>
// RRset; a stale GET inside the second writer's AppendRecords causes
// the PUT payload to omit (and therefore delete) the first writer's
// record.
//
// To make writes deterministic regardless of API read consistency,
// Client maintains an in-memory authoritative cache of TXT records
// it has added. Every PUT merges the API's current zone state with
// this cache, so a stale GET cannot lose records this Client already
// wrote. The mutex serializes operations on a single Client, which is
// shared across all challenges via the solver.
type Client struct {
	api *httpAPI

	mu sync.Mutex
	// cache: zone -> our TXT records (key=(absName,value)) -> ttl.
	// Cache is the source of truth for records this Client wrote, and
	// is unioned into every PUT payload to compensate for API stale reads.
	cache map[string]map[txtKey]int
}

// NewClient creates a new mijn.host DNS client with the given API key.
// A single Client must be reused across requests so the mutex serializes
// concurrent writes and the cache survives between calls.
func NewClient(apiKey string) *Client {
	return &Client{
		api:   newHTTPAPI(apiKey),
		cache: make(map[string]map[txtKey]int),
	}
}

// AddTXTRecord adds a TXT record to the given zone.
//
// Idempotent: if the record is already in our cache, no API calls happen.
// Otherwise: GET the zone, union the API view with our cache (cache wins
// for our records, API contributes everything else), append the new
// record, PUT the merged set, then update the cache. The cache merge is
// what defends against the API's stale read view.
func (c *Client) AddTXTRecord(ctx context.Context, zone, name, value string, ttl int) error {
	zone = strings.TrimSuffix(zone, ".")
	absName := absoluteName(name, zone)
	key := txtKey{name: absName, value: value}

	c.mu.Lock()
	defer c.mu.Unlock()

	if zc := c.cache[zone]; zc != nil {
		if _, ok := zc[key]; ok {
			return nil
		}
	}

	apiRecords, err := c.api.getRecords(ctx, zone)
	if err != nil {
		return err
	}

	desired := mergeRecords(apiRecords, c.cache[zone])
	desired = appendIfMissing(desired, DNSRecord{
		Type:  "TXT",
		Name:  absName,
		Value: value,
		TTL:   ttl,
	})

	if err := c.api.putRecords(ctx, zone, desired); err != nil {
		return err
	}

	if c.cache[zone] == nil {
		c.cache[zone] = make(map[txtKey]int)
	}
	c.cache[zone][key] = ttl
	return nil
}

// RemoveTXTRecord removes a TXT record from the given zone.
//
// Idempotent: if the record is neither in the API response nor our cache,
// returns nil without issuing a PUT. Otherwise: GET, merge with cache,
// drop the record, PUT, update cache.
func (c *Client) RemoveTXTRecord(ctx context.Context, zone, name, value string) error {
	zone = strings.TrimSuffix(zone, ".")
	absName := absoluteName(name, zone)
	key := txtKey{name: absName, value: value}

	c.mu.Lock()
	defer c.mu.Unlock()

	apiRecords, err := c.api.getRecords(ctx, zone)
	if err != nil {
		return err
	}

	inCache := false
	if zc := c.cache[zone]; zc != nil {
		_, inCache = zc[key]
	}
	inAPI := false
	for _, r := range apiRecords {
		if r.Type == "TXT" && r.Name == absName && r.Value == value {
			inAPI = true
			break
		}
	}
	if !inCache && !inAPI {
		return nil
	}

	desired := mergeRecords(apiRecords, c.cache[zone])
	desired = removeRecord(desired, "TXT", absName, value)

	if err := c.api.putRecords(ctx, zone, desired); err != nil {
		return err
	}

	if c.cache[zone] != nil {
		delete(c.cache[zone], key)
	}
	return nil
}

// mergeRecords returns the union of API records and cached TXT records,
// deduped by (type, name, value). Cached records win on TTL when the
// dedup key matches.
func mergeRecords(api []DNSRecord, cache map[txtKey]int) []DNSRecord {
	out := make([]DNSRecord, 0, len(api)+len(cache))
	seen := make(map[recordID]bool, len(api)+len(cache))

	for k, ttl := range cache {
		id := recordID{Type: "TXT", Name: k.name, Value: k.value}
		seen[id] = true
		out = append(out, DNSRecord{
			Type:  "TXT",
			Name:  k.name,
			Value: k.value,
			TTL:   ttl,
		})
	}
	for _, r := range api {
		id := recordID{Type: r.Type, Name: r.Name, Value: r.Value}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, r)
	}
	return out
}

// appendIfMissing adds r to records if no entry with the same
// (type, name, value) is already present.
func appendIfMissing(records []DNSRecord, r DNSRecord) []DNSRecord {
	for _, existing := range records {
		if existing.Type == r.Type && existing.Name == r.Name && existing.Value == r.Value {
			return records
		}
	}
	return append(records, r)
}

// removeRecord returns records with any entry matching (type, name, value)
// removed.
func removeRecord(records []DNSRecord, recType, name, value string) []DNSRecord {
	out := records[:0]
	for _, r := range records {
		if r.Type == recType && r.Name == name && r.Value == value {
			continue
		}
		out = append(out, r)
	}
	return out
}

// absoluteName returns the FQDN form (with trailing dot) of name relative
// to zone, matching how the mijn.host API stores names. zone may be passed
// with or without a trailing dot; name may already be relative or absolute.
func absoluteName(name, zone string) string {
	name = strings.TrimSuffix(name, ".")
	zone = strings.TrimSuffix(zone, ".")
	if name == "" || name == "@" {
		return zone + "."
	}
	if name == zone || strings.HasSuffix(name, "."+zone) {
		return name + "."
	}
	return name + "." + zone + "."
}
