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
)

const defaultBaseURL = "https://mijn.host/api/v2/"

// DNSRecord mirrors the mijn.host API JSON shape for a single DNS record.
type DNSRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

// httpAPI is a minimal mijn.host HTTP client for the /domains/{zone}/dns
// endpoint. It exposes the full-zone GET and PUT operations directly, with
// no Get-Modify-PUT helpers — that combination is what the eventually
// consistent mijn.host read view turns into a race when concurrent
// callers (e.g. wildcard apex+SAN challenges) write to the same RRset.
// The Client wrapper holds an authoritative cache and computes the PUT
// payload itself so a stale GET cannot lose previously written records.
type httpAPI struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

func newHTTPAPI(apiKey string) *httpAPI {
	return &httpAPI{
		baseURL: defaultBaseURL,
		apiKey:  apiKey,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
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

// getRecords fetches the full DNS record set for zone.
func (a *httpAPI) getRecords(ctx context.Context, zone string) ([]DNSRecord, error) {
	var resp struct {
		apiStatus
		Data struct {
			Records []DNSRecord `json:"records"`
		} `json:"data"`
	}
	if err := a.do(ctx, http.MethodGet, a.dnsPath(zone), nil, &resp); err != nil {
		return nil, err
	}
	if err := resp.apiStatus.err(); err != nil {
		return nil, err
	}
	return resp.Data.Records, nil
}

// putRecords replaces the full DNS record set for zone.
func (a *httpAPI) putRecords(ctx context.Context, zone string, records []DNSRecord) error {
	body, err := json.Marshal(struct {
		Records []DNSRecord `json:"records"`
	}{records})
	if err != nil {
		return err
	}
	var resp apiStatus
	if err := a.do(ctx, http.MethodPut, a.dnsPath(zone), bytes.NewReader(body), &resp); err != nil {
		return err
	}
	return resp.err()
}

func (a *httpAPI) dnsPath(zone string) string {
	return fmt.Sprintf("domains/%s/dns", url.PathEscape(strings.TrimSuffix(zone, ".")))
}

func (a *httpAPI) do(ctx context.Context, method, path string, body io.Reader, out any) error {
	base, err := url.Parse(a.baseURL)
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
	req.Header.Set("api-key", a.apiKey)
	req.Header.Set("user-agent", "cert-manager-webhook-mijn-host")

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if !strings.HasPrefix(resp.Header.Get("content-type"), "application/json") {
		return fmt.Errorf("mijn.host API returned non-JSON response (status %d)", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
