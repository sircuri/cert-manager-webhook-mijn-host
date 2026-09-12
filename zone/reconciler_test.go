package zone

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/sircuri/cert-manager-webhook-mijn-host/mijnhost"
)

const testZone = "example.nl"

var testSecret = SecretRef{Namespace: "cert-manager", Name: "mijn-host-api-key", Key: "api-key"}

type testEnv struct {
	kube  kubernetes.Interface
	dns   *fakeDNS
	clock *fixedClock
	rec   *Reconciler
	store *ConfigMapStore
}

func newTestEnv(t *testing.T, initial ...mijnhost.DNSRecord) *testEnv {
	t.Helper()
	return newTestEnvWith(t, Options{OwnAcmeRecords: true}, initial...)
}

func newTestEnvWith(t *testing.T, opts Options, initial ...mijnhost.DNSRecord) *testEnv {
	t.Helper()
	kube := newFakeKube()
	clock := &fixedClock{t: time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)}
	dns := newFakeDNS(testZone, initial...)
	store := NewConfigMapStore(kube, "cert-manager")
	lock := NewLeaseLock(kube, "cert-manager", "pod-a", LeaseLockOptions{
		Duration: time.Minute, WaitTimeout: 2 * time.Second, PollInterval: time.Millisecond, Now: clock.now,
	})
	opts.Now = clock.now
	rec := NewReconciler(lock, store,
		func(string) DNSAPI { return dns },
		func(_ context.Context, ref SecretRef) (string, error) {
			if ref != testSecret {
				return "", errors.New("unknown secret " + ref.String())
			}
			return "key", nil
		},
		opts)
	return &testEnv{kube: kube, dns: dns, clock: clock, rec: rec, store: store}
}

func request(name, value string) Request {
	return Request{Zone: testZone + ".", Name: name, Value: value, TTL: 300, ChallengeUID: "uid-" + value, DNSName: strings.TrimPrefix(name, "_acme-challenge."), APIKeySecretRef: testSecret}
}

func (e *testEnv) desired(t *testing.T) []string {
	t.Helper()
	h, err := e.store.Load(context.Background(), testZone)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	return Describe(desiredRecords(h.State))
}

func TestPresent_WritesRecordAndStoresState(t *testing.T) {
	e := newTestEnv(t, recA, recSPF)

	if err := e.rec.Present(context.Background(), request("_acme-challenge.example.nl", "aaa")); err != nil {
		t.Fatalf("present: %v", err)
	}
	if !e.dns.has(testZone, recA) || !e.dns.has(testZone, recSPF) || !e.dns.has(testZone, chalA) {
		t.Fatalf("zone after present = %+v", e.dns.zones[testZone])
	}
	if got := e.desired(t); !equalStrings(got, Describe([]mijnhost.DNSRecord{chalA})) {
		t.Fatalf("desired = %v", got)
	}
	h, _ := e.store.Load(context.Background(), testZone)
	if h.State.APIKeySecretRef != testSecret || h.State.Records[0].ChallengeUID != "uid-aaa" {
		t.Fatalf("state = %+v", h.State)
	}
}

func TestPresent_RepeatedIsNoWriteWhenInSync(t *testing.T) {
	e := newTestEnv(t, recA)
	req := request("_acme-challenge.example.nl", "aaa")
	if err := e.rec.Present(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := e.rec.Present(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if e.dns.puts != 1 {
		t.Fatalf("expected 1 PUT, got %d", e.dns.puts)
	}
}

func TestPresent_RepairsRecordLostByStaleWrite(t *testing.T) {
	e := newTestEnv(t, recA)
	req := request("_acme-challenge.example.nl", "aaa")
	if err := e.rec.Present(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	// Something outside our control removed the record (e.g. an old webhook
	// version writing from a stale view).
	_ = e.dns.PutRecords(context.Background(), testZone, []mijnhost.DNSRecord{recA})

	if err := e.rec.Present(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if !e.dns.has(testZone, chalA) {
		t.Fatalf("record not repaired, zone = %v", e.dns.challenges(testZone))
	}
}

func TestPresent_StaleReadDoesNotLoseEarlierRecord(t *testing.T) {
	e := newTestEnv(t, recA)
	if err := e.rec.Present(context.Background(), request("_acme-challenge.example.nl", "aaa")); err != nil {
		t.Fatal(err)
	}
	// The API serves the pre-write zone for the next GET, as mijn.host does.
	e.dns.makeStale(1)
	_ = e.dns.PutRecords(context.Background(), testZone, e.dns.lastPut) // keep zone, refresh snapshot semantics
	e.dns.snapshot[testZone] = []mijnhost.DNSRecord{recA}               // stale view without aaa

	if err := e.rec.Present(context.Background(), request("_acme-challenge.other.example.nl", "bbb")); err != nil {
		t.Fatal(err)
	}
	want := Describe([]mijnhost.DNSRecord{chalA, txt("_acme-challenge.other.example.nl.", "bbb")})
	if got := e.dns.challenges(testZone); !equalStrings(got, want) {
		t.Fatalf("zone challenges = %v, want %v", got, want)
	}
}

func TestCleanUp_RemovesRecordAndState(t *testing.T) {
	e := newTestEnv(t, recA)
	req := request("_acme-challenge.example.nl", "aaa")
	if err := e.rec.Present(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := e.rec.CleanUp(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if e.dns.has(testZone, chalA) || !e.dns.has(testZone, recA) {
		t.Fatalf("zone after cleanup = %+v", e.dns.zones[testZone])
	}
	if got := e.desired(t); len(got) != 0 {
		t.Fatalf("desired after cleanup = %v", got)
	}
}

func TestCleanUp_StaleReadStillShowingRecordDoesNotResurrectIt(t *testing.T) {
	e := newTestEnv(t, recA)
	req := request("_acme-challenge.example.nl", "aaa")
	if err := e.rec.Present(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := e.rec.CleanUp(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	// Next GET returns the zone as it was before cleanup.
	e.dns.snapshot[testZone] = []mijnhost.DNSRecord{recA, chalA}
	e.dns.stale = 1

	if err := e.rec.Present(context.Background(), request("_acme-challenge.example.nl", "bbb")); err != nil {
		t.Fatal(err)
	}
	if got := e.dns.challenges(testZone); !equalStrings(got, Describe([]mijnhost.DNSRecord{chalB})) {
		t.Fatalf("zone challenges = %v", got)
	}
}

func TestCleanUp_UnknownRecordIsNotAnError(t *testing.T) {
	e := newTestEnv(t, recA)
	if err := e.rec.CleanUp(context.Background(), request("_acme-challenge.example.nl", "never-added")); err != nil {
		t.Fatalf("cleanup of unknown record: %v", err)
	}
	if e.dns.puts != 0 {
		t.Fatalf("expected no PUT, got %d", e.dns.puts)
	}
}

func TestCleanUp_RemovesLeftoverEvenIfStaleReadHidesIt(t *testing.T) {
	// Leftover in the zone, unknown to state; CleanUp's GET hides it.
	// The PUT still happens because ownAll makes the desired set
	// authoritative only when there is a difference; here the stale view
	// matches desired (empty), so no PUT. The sweep catches it later.
	e := newTestEnv(t, recA, chalOld)
	e.dns.snapshot[testZone] = []mijnhost.DNSRecord{recA}
	e.dns.stale = 1
	if err := e.rec.CleanUp(context.Background(), request("_acme-challenge.dev.example.nl", "leftover")); err != nil {
		t.Fatal(err)
	}
	if err := e.rec.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.dns.has(testZone, chalOld) {
		t.Fatalf("leftover survived sweep: %v", e.dns.challenges(testZone))
	}
}

func TestSweep_RemovesLeftoversKeepsDesired(t *testing.T) {
	e := newTestEnv(t, recA, chalOld)
	req := request("_acme-challenge.example.nl", "aaa")
	if err := e.rec.Present(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	// Present already dropped the leftover. Put it back to simulate a
	// leftover appearing after the last write.
	_ = e.dns.PutRecords(context.Background(), testZone, []mijnhost.DNSRecord{recA, chalA, chalOld})

	if err := e.rec.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := e.dns.challenges(testZone); !equalStrings(got, Describe([]mijnhost.DNSRecord{chalA})) {
		t.Fatalf("zone challenges after sweep = %v", got)
	}
}

func TestSweep_NoWriteWhenInSync(t *testing.T) {
	e := newTestEnv(t, recA)
	if err := e.rec.Present(context.Background(), request("_acme-challenge.example.nl", "aaa")); err != nil {
		t.Fatal(err)
	}
	puts := e.dns.puts
	if err := e.rec.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.dns.puts != puts {
		t.Fatalf("sweep wrote although zone was in sync")
	}
}

func TestSweep_SkipsZonesWithoutState(t *testing.T) {
	e := newTestEnv(t, recA, chalOld)
	if err := e.rec.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.dns.gets != 0 {
		t.Fatalf("sweep touched a zone that has no state")
	}
}

func TestSweep_ExpiresOldRecords(t *testing.T) {
	e := newTestEnvWith(t, Options{OwnAcmeRecords: true, MaxRecordAge: time.Hour}, recA)
	if err := e.rec.Present(context.Background(), request("_acme-challenge.example.nl", "aaa")); err != nil {
		t.Fatal(err)
	}
	e.clock.advance(2 * time.Hour)
	if err := e.rec.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.dns.has(testZone, chalA) {
		t.Fatalf("expired record still in zone")
	}
	if got := e.desired(t); len(got) != 0 {
		t.Fatalf("expired record still desired: %v", got)
	}
}

func TestPresent_PutFailureKeepsIntentForRetry(t *testing.T) {
	e := newTestEnv(t, recA)
	e.dns.putErr = errors.New("mijn.host 502")
	req := request("_acme-challenge.example.nl", "aaa")
	if err := e.rec.Present(context.Background(), req); err == nil {
		t.Fatal("expected error from failed PUT")
	}
	if got := e.desired(t); !equalStrings(got, Describe([]mijnhost.DNSRecord{chalA})) {
		t.Fatalf("intent not stored before PUT: %v", got)
	}
	e.dns.putErr = nil
	if err := e.rec.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !e.dns.has(testZone, chalA) {
		t.Fatal("sweep did not complete the failed write")
	}
}

func TestNotOwnAll_KeepsForeignChallengeRecords(t *testing.T) {
	e := newTestEnvWith(t, Options{OwnAcmeRecords: false}, recA, chalOld)
	req := request("_acme-challenge.example.nl", "aaa")
	if err := e.rec.Present(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if !e.dns.has(testZone, chalOld) || !e.dns.has(testZone, chalA) {
		t.Fatalf("zone = %v", e.dns.challenges(testZone))
	}
	if err := e.rec.CleanUp(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if !e.dns.has(testZone, chalOld) || e.dns.has(testZone, chalA) {
		t.Fatalf("zone after cleanup = %v", e.dns.challenges(testZone))
	}
}

func TestConcurrentPresentsAreSerialized(t *testing.T) {
	e := newTestEnv(t, recA)
	var inside, violations int32
	var mu sync.Mutex
	e.dns.onGet = func() {
		mu.Lock()
		inside++
		if inside > 1 {
			violations++
		}
		mu.Unlock()
		time.Sleep(2 * time.Millisecond)
		mu.Lock()
		inside--
		mu.Unlock()
	}

	values := []string{"a", "b", "c", "d", "e", "f"}
	var wg sync.WaitGroup
	for _, v := range values {
		wg.Add(1)
		go func(v string) {
			defer wg.Done()
			if err := e.rec.Present(context.Background(), request("_acme-challenge."+v+".example.nl", v)); err != nil {
				t.Errorf("present %s: %v", v, err)
			}
		}(v)
	}
	wg.Wait()

	if violations != 0 {
		t.Fatalf("%d overlapping zone operations", violations)
	}
	if got := e.dns.challenges(testZone); len(got) != len(values) {
		t.Fatalf("zone challenges = %v", got)
	}
}

func TestReconcile_RefusesToWriteWhenAPIReturnsEmptyZone(t *testing.T) {
	// The API answers with no records at all (broken or truncated response).
	// Writing anything now would wipe the zone, so nothing may be written.
	e := newTestEnv(t)
	err := e.rec.Present(context.Background(), request("_acme-challenge.example.nl", "aaa"))
	if !errors.Is(err, ErrEmptyZone) {
		t.Fatalf("expected ErrEmptyZone, got %v", err)
	}
	if e.dns.puts != 0 {
		t.Fatalf("PUT was sent against an empty zone view")
	}
	// The intent is kept, so the record is written once the API is sane again.
	_ = e.dns.PutRecords(context.Background(), testZone, []mijnhost.DNSRecord{recA})
	if err := e.rec.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !e.dns.has(testZone, chalA) {
		t.Fatal("record not written after API recovered")
	}
}

func TestReconcile_RefusesToWriteWhenAPIReturnsOnlyChallengeRecords(t *testing.T) {
	e := newTestEnv(t, chalOld)
	err := e.rec.Present(context.Background(), request("_acme-challenge.example.nl", "aaa"))
	if !errors.Is(err, ErrEmptyZone) {
		t.Fatalf("expected ErrEmptyZone, got %v", err)
	}
	if e.dns.puts != 0 {
		t.Fatalf("PUT was sent against a challenge-only zone view")
	}
}
