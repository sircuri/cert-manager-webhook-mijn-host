// Package mijnhost is a minimal client for the mijn.host DNS API.
//
// The API only offers full-zone operations: GET returns every record in a
// zone and PUT replaces every record in a zone. The API is also not
// read-your-writes consistent: a GET shortly after a PUT can return the zone
// as it was before the PUT. This package deliberately exposes nothing but
// those two calls. Deciding what a PUT must contain, and making sure only one
// caller writes a zone at a time, is the job of the zone package.
package mijnhost

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"
)

const defaultBaseURL = "https://mijn.host/api/v2/"

// DNSRecord mirrors the mijn.host API JSON shape for a single DNS record.
// Names are absolute with a trailing dot, e.g. "_acme-challenge.example.nl.".
type DNSRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

// Client talks to the mijn.host API for one API key. It holds no state
// between calls and is safe for concurrent use.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// NewClient creates a client for the given API key.
func NewClient(apiKey string) *Client {
	return &Client{
		baseURL: defaultBaseURL,
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// NewClientWithBaseURL creates a client against a custom API base URL. Used
// by tests that run a mock server.
func NewClientWithBaseURL(apiKey, baseURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{baseURL: baseURL, apiKey: apiKey, http: httpClient}
}

type apiStatus struct {
	Status            int    `json:"status"`
	StatusDescription string `json:"status_description"`
}

func (s apiStatus) err() error {
	if s.Status >= 200 && s.Status < 300 {
		return nil
	}
	return fmt.Errorf("mijn.host API status %d: %s", s.Status, s.StatusDescription)
}

// GetRecords fetches the full DNS record set for zone.
func (c *Client) GetRecords(ctx context.Context, zone string) ([]DNSRecord, error) {
	log := logr.FromContextOrDiscard(ctx)
	start := time.Now()

	var resp struct {
		apiStatus
		Data struct {
			Records []DNSRecord `json:"records"`
		} `json:"data"`
	}
	err := c.do(ctx, http.MethodGet, c.dnsPath(zone), nil, &resp)
	if err == nil {
		err = resp.err()
	}
	if err != nil {
		log.Error(err, "mijn.host GET failed", "zone", zone, "duration", time.Since(start).Round(time.Millisecond))
		return nil, fmt.Errorf("get records for zone %s: %w", zone, err)
	}
	log.Info("mijn.host GET", "zone", zone, "records", len(resp.Data.Records),
		"challengeRecords", countChallengeRecords(resp.Data.Records), "duration", time.Since(start).Round(time.Millisecond))
	return resp.Data.Records, nil
}

// PutRecords replaces the full DNS record set for zone.
func (c *Client) PutRecords(ctx context.Context, zone string, records []DNSRecord) error {
	log := logr.FromContextOrDiscard(ctx)
	start := time.Now()

	body, err := json.Marshal(struct {
		Records []DNSRecord `json:"records"`
	}{records})
	if err != nil {
		return err
	}
	var resp apiStatus
	err = c.do(ctx, http.MethodPut, c.dnsPath(zone), bytes.NewReader(body), &resp)
	if err == nil {
		err = resp.err()
	}
	if err != nil {
		log.Error(err, "mijn.host PUT failed", "zone", zone, "records", len(records), "duration", time.Since(start).Round(time.Millisecond))
		return fmt.Errorf("put records for zone %s: %w", zone, err)
	}
	log.Info("mijn.host PUT", "zone", zone, "records", len(records),
		"challengeRecords", countChallengeRecords(records), "duration", time.Since(start).Round(time.Millisecond))
	return nil
}

func countChallengeRecords(records []DNSRecord) int {
	n := 0
	for _, r := range records {
		if r.Type == "TXT" && strings.HasPrefix(r.Name, "_acme-challenge.") {
			n++
		}
	}
	return n
}

func (c *Client) dnsPath(zone string) string {
	return fmt.Sprintf("domains/%s/dns", url.PathEscape(strings.TrimSuffix(zone, ".")))
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, out any) error {
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return err
	}
	rel, err := url.Parse(path)
	if err != nil {
		return err
	}
	u := base.ResolveReference(rel)

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", "application/json")
	req.Header.Set("api-key", c.apiKey)
	req.Header.Set("user-agent", "cert-manager-webhook-mijn-host")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if !strings.HasPrefix(resp.Header.Get("content-type"), "application/json") {
		return fmt.Errorf("non-JSON response (HTTP %d)", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
