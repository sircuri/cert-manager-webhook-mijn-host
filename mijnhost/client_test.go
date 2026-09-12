package mijnhost

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// mockServer simulates the mijn.host API endpoints used by Client.
type mockServer struct {
	mu          sync.Mutex
	records     []DNSRecord
	server      *httptest.Server
	getCount    int
	putCount    int
	lastPutBody []DNSRecord
	lastAPIKey  string
	failStatus  int // when non-zero, respond with this API status on every call
}

func newMockServer(initial []DNSRecord) *mockServer {
	m := &mockServer{records: append([]DNSRecord(nil), initial...)}
	m.server = httptest.NewServer(http.HandlerFunc(m.handler))
	return m
}

func (m *mockServer) close() { m.server.Close() }

func (m *mockServer) handler(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Header().Set("content-type", "application/json")
	m.lastAPIKey = r.Header.Get("api-key")

	if m.failStatus != 0 {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":             m.failStatus,
			"status_description": "simulated failure",
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		m.getCount++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":             200,
			"status_description": "OK",
			"data": map[string]any{
				"domain":  "example.com",
				"records": m.records,
			},
		})
	case http.MethodPut:
		m.putCount++
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			Records []DNSRecord `json:"records"`
		}
		_ = json.Unmarshal(body, &payload)
		m.records = payload.Records
		m.lastPutBody = payload.Records
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":             200,
			"status_description": "OK",
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func newTestClient(m *mockServer) *Client {
	return NewClientWithBaseURL("test-api-key", m.server.URL+"/api/v2/", m.server.Client())
}

func TestGetRecords_ReturnsZone(t *testing.T) {
	initial := []DNSRecord{
		{Type: "A", Name: "example.com.", Value: "1.2.3.4", TTL: 900},
		{Type: "TXT", Name: "_acme-challenge.example.com.", Value: "tok", TTL: 300},
	}
	m := newMockServer(initial)
	defer m.close()

	got, err := newTestClient(m).GetRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[1].Value != "tok" {
		t.Fatalf("unexpected records: %+v", got)
	}
	if m.lastAPIKey != "test-api-key" {
		t.Errorf("api-key header not sent, got %q", m.lastAPIKey)
	}
}

func TestPutRecords_SendsFullZone(t *testing.T) {
	m := newMockServer(nil)
	defer m.close()

	want := []DNSRecord{
		{Type: "A", Name: "example.com.", Value: "1.2.3.4", TTL: 900},
		{Type: "TXT", Name: "_acme-challenge.example.com.", Value: "tok", TTL: 300},
	}
	if err := newTestClient(m).PutRecords(context.Background(), "example.com.", want); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.putCount != 1 {
		t.Fatalf("expected 1 PUT, got %d", m.putCount)
	}
	if len(m.lastPutBody) != 2 || m.lastPutBody[1] != want[1] {
		t.Fatalf("unexpected PUT body: %+v", m.lastPutBody)
	}
}

func TestAPIErrorStatusIsReturned(t *testing.T) {
	m := newMockServer(nil)
	defer m.close()
	m.failStatus = 401

	c := newTestClient(m)
	if _, err := c.GetRecords(context.Background(), "example.com"); err == nil {
		t.Fatal("expected error from GET")
	}
	if err := c.PutRecords(context.Background(), "example.com", nil); err == nil {
		t.Fatal("expected error from PUT")
	}
}

func TestNonJSONResponseIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>bad gateway</html>"))
	}))
	defer srv.Close()

	c := NewClientWithBaseURL("k", srv.URL+"/api/v2/", srv.Client())
	if _, err := c.GetRecords(context.Background(), "example.com"); err == nil {
		t.Fatal("expected error for non-JSON response")
	}
}
