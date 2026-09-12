package zone

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/sircuri/cert-manager-webhook-mijn-host/mijnhost"
)

// scriptedSerial returns serials from a script, one per call, repeating
// the last one. A zero entry simulates "no nameserver answered".
type scriptedSerial struct {
	mu     sync.Mutex
	script []uint32
	calls  int
}

func (s *scriptedSerial) Serial(context.Context, string) (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.calls
	s.calls++
	if i >= len(s.script) {
		i = len(s.script) - 1
	}
	if s.script[i] == 0 {
		return 0, ErrSerialUnavailable
	}
	return s.script[i], nil
}

func newSerialEnv(t *testing.T, script []uint32, required bool, initial ...mijnhost.DNSRecord) (*testEnv, *scriptedSerial) {
	t.Helper()
	ss := &scriptedSerial{script: script}
	e := newTestEnvWith(t, Options{
		OwnAcmeRecords:   true,
		Serial:           ss,
		SerialRequired:   required,
		MaxWriteAttempts: 3,
	}, initial...)
	return e, ss
}

func TestSerialCheck_UnchangedSerialWrites(t *testing.T) {
	// before read: 10, before write: 10 -> write.
	e, ss := newSerialEnv(t, []uint32{10, 10}, false, recA)
	if err := e.rec.Present(context.Background(), request("_acme-challenge.example.nl", "aaa")); err != nil {
		t.Fatal(err)
	}
	if e.dns.puts != 1 || !e.dns.has(testZone, chalA) {
		t.Fatalf("puts=%d zone=%v", e.dns.puts, e.dns.challenges(testZone))
	}
	if ss.calls != 2 {
		t.Fatalf("expected 2 serial reads (before read, before write), got %d", ss.calls)
	}
}

func TestSerialCheck_ChangedSerialStartsOver(t *testing.T) {
	// Attempt 1: read at 10, someone edits, before write it is 11 -> restart.
	// Attempt 2: read at 11, before write 11 -> write.
	e, ss := newSerialEnv(t, []uint32{10, 11, 11, 11}, false, recA)
	if err := e.rec.Present(context.Background(), request("_acme-challenge.example.nl", "aaa")); err != nil {
		t.Fatal(err)
	}
	if e.dns.gets != 2 {
		t.Fatalf("expected the zone to be re-read after the serial moved, gets=%d", e.dns.gets)
	}
	if e.dns.puts != 1 || !e.dns.has(testZone, chalA) {
		t.Fatalf("puts=%d zone=%v", e.dns.puts, e.dns.challenges(testZone))
	}
	if ss.calls != 4 {
		t.Fatalf("serial reads = %d, want 4", ss.calls)
	}
}

func TestSerialCheck_ConstantlyChangingZoneGivesUpWithoutWriting(t *testing.T) {
	// Every before-write read differs from the before-read read.
	e, _ := newSerialEnv(t, []uint32{1, 2, 3, 4, 5, 6, 7, 8}, false, recA)
	err := e.rec.Present(context.Background(), request("_acme-challenge.example.nl", "aaa"))
	if !errors.Is(err, ErrZoneChanging) {
		t.Fatalf("expected ErrZoneChanging, got %v", err)
	}
	if e.dns.puts != 0 {
		t.Fatalf("must not write over a zone that keeps changing, puts=%d", e.dns.puts)
	}
	if e.dns.gets != 3 {
		t.Fatalf("expected 3 attempts, gets=%d", e.dns.gets)
	}
	// The intent is kept: once the zone settles, the sweep writes it.
	e.rec.opts.Serial = &scriptedSerial{script: []uint32{9, 9}}
	if err := e.rec.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !e.dns.has(testZone, chalA) {
		t.Fatal("record not written after zone settled")
	}
}

func TestSerialCheck_UnavailableIsSkippedByDefault(t *testing.T) {
	e, _ := newSerialEnv(t, []uint32{0}, false, recA)
	if err := e.rec.Present(context.Background(), request("_acme-challenge.example.nl", "aaa")); err != nil {
		t.Fatalf("write must proceed without serial when nameservers are unreachable: %v", err)
	}
	if e.dns.puts != 1 {
		t.Fatalf("puts=%d", e.dns.puts)
	}
}

func TestSerialCheck_UnavailableFailsWhenRequired(t *testing.T) {
	e, _ := newSerialEnv(t, []uint32{0}, true, recA)
	err := e.rec.Present(context.Background(), request("_acme-challenge.example.nl", "aaa"))
	if !errors.Is(err, ErrSerialUnavailable) {
		t.Fatalf("expected ErrSerialUnavailable, got %v", err)
	}
	if e.dns.puts != 0 {
		t.Fatalf("puts=%d", e.dns.puts)
	}
}

func TestSerialCheck_NoSerialReadsWhenNothingToWrite(t *testing.T) {
	e, ss := newSerialEnv(t, []uint32{10}, false, recA, chalA)
	// Present of a record that is already in the zone: state gets it, GET
	// shows it, no write, so only the "before read" serial is fetched.
	if err := e.rec.Present(context.Background(), request("_acme-challenge.example.nl", "aaa")); err != nil {
		t.Fatal(err)
	}
	if e.dns.puts != 0 || ss.calls != 1 {
		t.Fatalf("puts=%d serialReads=%d", e.dns.puts, ss.calls)
	}
}

// DNSSerialReader against fake nameservers.

func fakeSOA(zone string, serial uint32) *dns.Msg {
	m := new(dns.Msg)
	m.Answer = []dns.RR{&dns.SOA{
		Hdr:    dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:     "ns1.example.org.",
		Mbox:   "hostmaster." + dns.Fqdn(zone),
		Serial: serial,
	}}
	return m
}

func newFakeSerialReader(servers map[string]uint32, nsErr error) (*DNSSerialReader, *int) {
	lookups := 0
	r := NewDNSSerialReader(time.Second)
	r.lookupNS = func(context.Context, string) ([]string, error) {
		lookups++
		if nsErr != nil {
			return nil, nsErr
		}
		out := []string{}
		for ns := range servers {
			out = append(out, ns)
		}
		return out, nil
	}
	r.exchange = func(_ context.Context, m *dns.Msg, addr string) (*dns.Msg, error) {
		host, _, _ := net.SplitHostPort(addr)
		serial, ok := servers[host]
		if !ok || serial == 0 {
			return nil, errors.New("i/o timeout")
		}
		return fakeSOA(m.Question[0].Name, serial), nil
	}
	return r, &lookups
}

func TestDNSSerialReader_ReturnsHighestSerialAcrossNameservers(t *testing.T) {
	r, _ := newFakeSerialReader(map[string]uint32{"ns1": 100, "ns2": 102, "ns3": 0}, nil)
	serial, err := r.Serial(context.Background(), "example.nl.")
	if err != nil || serial != 102 {
		t.Fatalf("serial=%d err=%v", serial, err)
	}
}

func TestDNSSerialReader_AllNameserversDownIsUnavailable(t *testing.T) {
	r, _ := newFakeSerialReader(map[string]uint32{"ns1": 0, "ns2": 0}, nil)
	if _, err := r.Serial(context.Background(), "example.nl"); !errors.Is(err, ErrSerialUnavailable) {
		t.Fatalf("expected ErrSerialUnavailable, got %v", err)
	}
}

func TestDNSSerialReader_NSLookupFailureIsUnavailable(t *testing.T) {
	r, _ := newFakeSerialReader(nil, errors.New("no such host"))
	if _, err := r.Serial(context.Background(), "example.nl"); !errors.Is(err, ErrSerialUnavailable) {
		t.Fatalf("expected ErrSerialUnavailable, got %v", err)
	}
}

func TestDNSSerialReader_CachesNameservers(t *testing.T) {
	r, lookups := newFakeSerialReader(map[string]uint32{"ns1": 5}, nil)
	for i := 0; i < 3; i++ {
		if _, err := r.Serial(context.Background(), "example.nl"); err != nil {
			t.Fatal(err)
		}
	}
	if *lookups != 1 {
		t.Fatalf("expected 1 NS lookup, got %d", *lookups)
	}
}

// TestDNSSerialReader_Live queries the real nameservers of the zone named in
// LIVE_ZONE. Skipped unless that variable is set; useful to confirm the
// NS discovery and SOA query work from a given network.
func TestDNSSerialReader_Live(t *testing.T) {
	zoneName := os.Getenv("LIVE_ZONE")
	if zoneName == "" {
		t.Skip("LIVE_ZONE not set")
	}
	r := NewDNSSerialReader(3 * time.Second)
	serial, err := r.Serial(context.Background(), zoneName)
	if err != nil {
		t.Fatalf("live serial for %s: %v", zoneName, err)
	}
	t.Logf("%s serial=%d nameservers=%v", zoneName, serial, r.nsCache[strings.TrimSuffix(zoneName, ".")])
	if serial == 0 {
		t.Fatal("serial is zero")
	}
}
