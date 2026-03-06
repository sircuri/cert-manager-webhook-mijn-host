package mijnhost

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	mh "github.com/libdns/mijnhost"
)

// dnsRecord mirrors the mijn.host API JSON format.
type dnsRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

// mockServer creates an httptest server that simulates the mijn.host API.
// It stores records in memory and handles GET/PUT on /api/v2/domains/{zone}/dns.
type mockServer struct {
	mu      sync.Mutex
	records []dnsRecord
	server  *httptest.Server
	// Track requests for assertions.
	requests []capturedRequest
}

type capturedRequest struct {
	Method string
	Path   string
	Body   string
}

func newMockServer(initial []dnsRecord) *mockServer {
	m := &mockServer{
		records: initial,
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.handler))
	return m
}

func (m *mockServer) handler(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	body, _ := io.ReadAll(r.Body)
	m.requests = append(m.requests, capturedRequest{
		Method: r.Method,
		Path:   r.URL.Path,
		Body:   string(body),
	})

	w.Header().Set("content-type", "application/json")

	switch r.Method {
	case http.MethodGet:
		resp := map[string]any{
			"status":             200,
			"status_description": "OK",
			"data": map[string]any{
				"domain":  "example.com",
				"records": m.records,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)

	case http.MethodPut:
		var payload struct {
			Records []dnsRecord `json:"records"`
		}
		_ = json.Unmarshal(body, &payload)
		m.records = payload.Records
		resp := map[string]any{
			"status":             200,
			"status_description": "OK",
		}
		_ = json.NewEncoder(w).Encode(resp)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *mockServer) close() {
	m.server.Close()
}

// newTestClient creates a Client backed by the mock server.
func newTestClient(m *mockServer) *Client {
	u, _ := url.Parse(m.server.URL + "/api/v2/")
	return &Client{
		provider: &mh.Provider{
			ApiKey:  "test-api-key",
			BaseUri: (*mh.ApiBaseUri)(u),
		},
	}
}

func TestAddTXTRecord_Success(t *testing.T) {
	m := newMockServer(nil)
	defer m.close()
	c := newTestClient(m)

	err := c.AddTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com", "token123", 300)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify records were set via PUT.
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(m.records))
	}
	rec := m.records[0]
	if rec.Type != "TXT" {
		t.Errorf("expected type TXT, got %s", rec.Type)
	}
	if rec.Value != "token123" {
		t.Errorf("expected value token123, got %s", rec.Value)
	}
	if rec.TTL != 300 {
		t.Errorf("expected TTL 300, got %d", rec.TTL)
	}
}

func TestAddTXTRecord_Idempotent(t *testing.T) {
	// Start with an existing matching record.
	m := newMockServer([]dnsRecord{
		{Type: "TXT", Name: "_acme-challenge.example.com.", Value: "token123", TTL: 300},
	})
	defer m.close()
	c := newTestClient(m)

	// First call — record exists, should be idempotent (no PUT).
	err := c.AddTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com", "token123", 300)
	if err != nil {
		t.Fatalf("first call: unexpected error: %v", err)
	}

	// Second call — still idempotent.
	err = c.AddTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com", "token123", 300)
	if err != nil {
		t.Fatalf("second call: unexpected error: %v", err)
	}

	// Verify only GET requests were made (no PUT since record already exists).
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, req := range m.requests {
		if req.Method == http.MethodPut {
			t.Error("expected no PUT requests for idempotent add, but found one")
		}
	}
}

func TestRemoveTXTRecord_Success(t *testing.T) {
	m := newMockServer([]dnsRecord{
		{Type: "TXT", Name: "_acme-challenge.example.com.", Value: "token123", TTL: 300},
		{Type: "A", Name: "example.com.", Value: "1.2.3.4", TTL: 3600},
	})
	defer m.close()
	c := newTestClient(m)

	err := c.RemoveTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com", "token123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The TXT record should be removed; the A record should remain.
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.records) != 1 {
		t.Fatalf("expected 1 remaining record, got %d", len(m.records))
	}
	if m.records[0].Type != "A" {
		t.Errorf("expected remaining record to be A, got %s", m.records[0].Type)
	}
}

func TestRemoveTXTRecord_NotFound(t *testing.T) {
	m := newMockServer([]dnsRecord{
		{Type: "A", Name: "example.com.", Value: "1.2.3.4", TTL: 3600},
	})
	defer m.close()
	c := newTestClient(m)

	// Removing a non-existent TXT record should return nil.
	err := c.RemoveTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com", "token123")
	if err != nil {
		t.Fatalf("expected nil error for non-existent record, got: %v", err)
	}

	// No PUT should have been made since nothing to delete.
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, req := range m.requests {
		if req.Method == http.MethodPut {
			t.Error("expected no PUT requests when record not found, but found one")
		}
	}
}

func TestAddTXTRecord_TrailingDot(t *testing.T) {
	m := newMockServer(nil)
	defer m.close()
	c := newTestClient(m)

	// Pass name with trailing dot (as cert-manager typically does).
	err := c.AddTXTRecord(context.Background(), "example.com.", "_acme-challenge.example.com.", "dottoken", 600)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(m.records))
	}
	rec := m.records[0]
	if rec.Type != "TXT" {
		t.Errorf("expected type TXT, got %s", rec.Type)
	}
	if rec.Value != "dottoken" {
		t.Errorf("expected value dottoken, got %s", rec.Value)
	}
}

func TestAddTXTRecord_APIError(t *testing.T) {
	// Create a server that returns an error status.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":             500,
			"status_description": "Internal Server Error",
			"data": map[string]any{
				"domain":  "example.com",
				"records": []any{},
			},
		})
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/api/v2/")
	c := &Client{
		provider: &mh.Provider{
			ApiKey:  "test-api-key",
			BaseUri: (*mh.ApiBaseUri)(u),
		},
	}

	err := c.AddTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com", "token", 300)
	if err == nil {
		t.Fatal("expected error from API, got nil")
	}
}
