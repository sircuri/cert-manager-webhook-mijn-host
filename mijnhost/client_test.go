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

// mockServer simulates the mijn.host API. By default it is strongly
// consistent: a PUT updates state immediately and the next GET returns it.
// Set staleReads > 0 to make the next N GETs return the previous (pre-PUT)
// state, which is the failure mode that breaks wildcard issuance on the
// real API.
type mockServer struct {
	mu          sync.Mutex
	records     []DNSRecord
	stale       []DNSRecord
	staleReads  int
	server      *httptest.Server
	getCount    int
	putCount    int
	lastPutBody []DNSRecord
}

func newMockServer(initial []DNSRecord) *mockServer {
	m := &mockServer{
		records: append([]DNSRecord(nil), initial...),
		stale:   append([]DNSRecord(nil), initial...),
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.handler))
	return m
}

func (m *mockServer) close() { m.server.Close() }

func (m *mockServer) setStaleReads(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stale = append([]DNSRecord(nil), m.records...)
	m.staleReads = n
}

func (m *mockServer) handler(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Header().Set("content-type", "application/json")

	switch r.Method {
	case http.MethodGet:
		m.getCount++
		view := m.records
		if m.staleReads > 0 {
			view = m.stale
			m.staleReads--
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":             200,
			"status_description": "OK",
			"data": map[string]any{
				"domain":  "example.com",
				"records": view,
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
		// Stale view sticks at its prior snapshot until staleReads drains.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":             200,
			"status_description": "OK",
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func newTestClient(m *mockServer) *Client {
	return &Client{
		api: &httpAPI{
			baseURL: m.server.URL + "/api/v2/",
			apiKey:  "test-api-key",
			client:  m.server.Client(),
		},
		cache: make(map[string]map[txtKey]int),
	}
}

func hasTXT(records []DNSRecord, name, value string) bool {
	for _, r := range records {
		if r.Type == "TXT" && r.Name == name && r.Value == value {
			return true
		}
	}
	return false
}

func TestAddTXTRecord_PUTsRecord(t *testing.T) {
	m := newMockServer(nil)
	defer m.close()
	c := newTestClient(m)

	if err := c.AddTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com", "token", 300); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if m.putCount != 1 {
		t.Fatalf("expected 1 PUT, got %d", m.putCount)
	}
	if !hasTXT(m.records, "_acme-challenge.example.com.", "token") {
		t.Errorf("PUT body did not contain expected TXT record: %+v", m.records)
	}
}

func TestAddTXTRecord_IdempotentFromCache(t *testing.T) {
	m := newMockServer(nil)
	defer m.close()
	c := newTestClient(m)

	for i := 0; i < 3; i++ {
		if err := c.AddTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com", "token", 300); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}

	if m.putCount != 1 {
		t.Errorf("expected exactly 1 PUT (cache should suppress repeats), got %d", m.putCount)
	}
}

func TestAddTXTRecord_PreservesOtherRecords(t *testing.T) {
	m := newMockServer([]DNSRecord{
		{Type: "A", Name: "example.com.", Value: "1.2.3.4", TTL: 3600},
		{Type: "MX", Name: "example.com.", Value: "10 mail.example.com.", TTL: 3600},
	})
	defer m.close()
	c := newTestClient(m)

	if err := c.AddTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com", "token", 300); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasTXT(m.records, "_acme-challenge.example.com.", "token") {
		t.Error("TXT record missing after PUT")
	}
	if !containsRecord(m.records, "A", "example.com.", "1.2.3.4") {
		t.Error("A record was wiped by PUT")
	}
	if !containsRecord(m.records, "MX", "example.com.", "10 mail.example.com.") {
		t.Error("MX record was wiped by PUT")
	}
}

func TestAddTXTRecord_StaleReadDoesNotClobberPriorWrite(t *testing.T) {
	// The smoking-gun scenario: two challenges write to the same RRset.
	// After the first write, the API briefly returns the pre-write zone
	// state. Without the cache, the second write's PUT payload would be
	// computed from that stale read and would clobber the first record.
	m := newMockServer(nil)
	defer m.close()
	c := newTestClient(m)

	if err := c.AddTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com", "first", 300); err != nil {
		t.Fatalf("first add: %v", err)
	}

	// Make the next GET return the pre-write state (no records).
	m.setStaleReads(1)

	if err := c.AddTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com", "second", 300); err != nil {
		t.Fatalf("second add: %v", err)
	}

	if !hasTXT(m.records, "_acme-challenge.example.com.", "first") {
		t.Error("first TXT was clobbered by stale-read PUT — cache merge failed")
	}
	if !hasTXT(m.records, "_acme-challenge.example.com.", "second") {
		t.Error("second TXT missing from PUT body")
	}
}

func TestAddTXTRecord_ConcurrentPresent(t *testing.T) {
	m := newMockServer([]DNSRecord{
		{Type: "A", Name: "example.com.", Value: "1.2.3.4", TTL: 3600},
	})
	defer m.close()
	c := newTestClient(m)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = c.AddTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com", "apex-token", 300)
	}()
	go func() {
		defer wg.Done()
		errs[1] = c.AddTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com", "wildcard-token", 300)
	}()
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}

	if !hasTXT(m.records, "_acme-challenge.example.com.", "apex-token") {
		t.Error("apex token missing from final zone")
	}
	if !hasTXT(m.records, "_acme-challenge.example.com.", "wildcard-token") {
		t.Error("wildcard token missing from final zone")
	}
	if !containsRecord(m.records, "A", "example.com.", "1.2.3.4") {
		t.Error("A record wiped during concurrent writes")
	}
}

func TestRemoveTXTRecord_RemovesOnlyMatching(t *testing.T) {
	m := newMockServer([]DNSRecord{
		{Type: "TXT", Name: "_acme-challenge.example.com.", Value: "keep", TTL: 300},
		{Type: "TXT", Name: "_acme-challenge.example.com.", Value: "drop", TTL: 300},
		{Type: "A", Name: "example.com.", Value: "1.2.3.4", TTL: 3600},
	})
	defer m.close()
	c := newTestClient(m)

	if err := c.RemoveTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com", "drop"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasTXT(m.records, "_acme-challenge.example.com.", "drop") {
		t.Error("dropped TXT still present after Remove")
	}
	if !hasTXT(m.records, "_acme-challenge.example.com.", "keep") {
		t.Error("non-matching TXT was incorrectly removed")
	}
	if !containsRecord(m.records, "A", "example.com.", "1.2.3.4") {
		t.Error("A record removed by RemoveTXT")
	}
}

func TestRemoveTXTRecord_NoOpWhenAbsent(t *testing.T) {
	m := newMockServer([]DNSRecord{
		{Type: "A", Name: "example.com.", Value: "1.2.3.4", TTL: 3600},
	})
	defer m.close()
	c := newTestClient(m)

	if err := c.RemoveTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com", "ghost"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if m.putCount != 0 {
		t.Errorf("expected no PUT for absent record, got %d", m.putCount)
	}
}

func TestRemoveTXTRecord_ConcurrentCleanUp(t *testing.T) {
	m := newMockServer([]DNSRecord{
		{Type: "A", Name: "example.com.", Value: "1.2.3.4", TTL: 3600},
		{Type: "TXT", Name: "_acme-challenge.example.com.", Value: "apex-token", TTL: 300},
		{Type: "TXT", Name: "_acme-challenge.example.com.", Value: "wildcard-token", TTL: 300},
	})
	defer m.close()
	c := newTestClient(m)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = c.RemoveTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com", "apex-token")
	}()
	go func() {
		defer wg.Done()
		errs[1] = c.RemoveTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com", "wildcard-token")
	}()
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}

	if hasTXT(m.records, "_acme-challenge.example.com.", "apex-token") {
		t.Error("apex token not removed")
	}
	if hasTXT(m.records, "_acme-challenge.example.com.", "wildcard-token") {
		t.Error("wildcard token not removed")
	}
	if !containsRecord(m.records, "A", "example.com.", "1.2.3.4") {
		t.Error("A record wiped during cleanup")
	}
}

func TestAddTXTRecord_TrailingDotNormalization(t *testing.T) {
	m := newMockServer(nil)
	defer m.close()
	c := newTestClient(m)

	if err := c.AddTXTRecord(context.Background(), "example.com.", "_acme-challenge.example.com.", "token", 300); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasTXT(m.records, "_acme-challenge.example.com.", "token") {
		t.Errorf("name normalization failed: %+v", m.records)
	}
}

func TestAddTXTRecord_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":             500,
			"status_description": "Internal Server Error",
			"data":               map[string]any{"domain": "example.com", "records": []any{}},
		})
	}))
	defer srv.Close()

	c := &Client{
		api:   &httpAPI{baseURL: srv.URL + "/api/v2/", apiKey: "k", client: srv.Client()},
		cache: make(map[string]map[txtKey]int),
	}

	if err := c.AddTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com", "token", 300); err == nil {
		t.Fatal("expected API error, got nil")
	}
}

func containsRecord(records []DNSRecord, recType, name, value string) bool {
	for _, r := range records {
		if r.Type == recType && r.Name == name && r.Value == value {
			return true
		}
	}
	return false
}
