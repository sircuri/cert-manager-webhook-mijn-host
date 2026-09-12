package zone

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/sircuri/cert-manager-webhook-mijn-host/mijnhost"
)

// newFakeKube returns a fake clientset whose create/update calls behave like
// a real apiserver with regard to resourceVersion: creates start at "1",
// every update bumps the version, and an update with a stale version fails
// with a Conflict. The stock fake tracker ignores resourceVersion entirely,
// which would make the lock's compare-and-swap untestable.
func newFakeKube() *fake.Clientset {
	cs := fake.NewClientset()
	var mu sync.Mutex
	versions := map[string]int{} // "resource/ns/name" -> version

	key := func(gvr schema.GroupVersionResource, ns, name string) string {
		return gvr.Resource + "/" + ns + "/" + name
	}
	cs.PrependReactor("create", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		a := action.(k8stesting.CreateAction)
		obj := a.GetObject()
		meta, err := metaOf(obj)
		if err != nil {
			return false, nil, nil
		}
		mu.Lock()
		defer mu.Unlock()
		k := key(a.GetResource(), a.GetNamespace(), meta.GetName())
		if _, exists := versions[k]; exists {
			return true, nil, apierrors.NewAlreadyExists(a.GetResource().GroupResource(), meta.GetName())
		}
		versions[k] = 1
		meta.SetResourceVersion("1")
		return false, nil, nil
	})
	cs.PrependReactor("update", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		a := action.(k8stesting.UpdateAction)
		obj := a.GetObject()
		meta, err := metaOf(obj)
		if err != nil {
			return false, nil, nil
		}
		mu.Lock()
		defer mu.Unlock()
		k := key(a.GetResource(), a.GetNamespace(), meta.GetName())
		current, exists := versions[k]
		if !exists {
			return true, nil, apierrors.NewNotFound(a.GetResource().GroupResource(), meta.GetName())
		}
		if meta.GetResourceVersion() != strconv.Itoa(current) {
			return true, nil, apierrors.NewConflict(a.GetResource().GroupResource(), meta.GetName(), errors.New("stale resourceVersion"))
		}
		versions[k] = current + 1
		meta.SetResourceVersion(strconv.Itoa(current + 1))
		return false, nil, nil
	})
	return cs
}

func metaOf(obj runtime.Object) (metav1.Object, error) {
	m, ok := obj.(metav1.Object)
	if !ok {
		return nil, errors.New("not a metav1.Object")
	}
	return m, nil
}

// fakeDNS is an in-memory mijn.host zone with controllable stale reads.
type fakeDNS struct {
	mu       sync.Mutex
	zones    map[string][]mijnhost.DNSRecord
	snapshot map[string][]mijnhost.DNSRecord // stale view served while staleReads > 0
	stale    int
	gets     int
	puts     int
	putErr   error
	lastPut  []mijnhost.DNSRecord
	onGet    func() // hook for concurrency tests
}

func newFakeDNS(zone string, initial ...mijnhost.DNSRecord) *fakeDNS {
	return &fakeDNS{
		zones:    map[string][]mijnhost.DNSRecord{zone: append([]mijnhost.DNSRecord(nil), initial...)},
		snapshot: map[string][]mijnhost.DNSRecord{},
	}
}

// makeStale serves the current zone contents for the next n GETs, even after
// PUTs change the zone. This is the mijn.host read-after-write behaviour.
func (f *fakeDNS) makeStale(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for z, recs := range f.zones {
		f.snapshot[z] = append([]mijnhost.DNSRecord(nil), recs...)
	}
	f.stale = n
}

func (f *fakeDNS) GetRecords(_ context.Context, zone string) ([]mijnhost.DNSRecord, error) {
	f.mu.Lock()
	f.gets++
	view := f.zones[zone]
	if f.stale > 0 {
		view = f.snapshot[zone]
		f.stale--
	}
	out := append([]mijnhost.DNSRecord(nil), view...)
	hook := f.onGet
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	return out, nil
}

func (f *fakeDNS) PutRecords(_ context.Context, zone string, records []mijnhost.DNSRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts++
	if f.putErr != nil {
		return f.putErr
	}
	f.zones[zone] = append([]mijnhost.DNSRecord(nil), records...)
	f.lastPut = f.zones[zone]
	return nil
}

func (f *fakeDNS) challenges(zone string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []mijnhost.DNSRecord
	for _, r := range f.zones[zone] {
		if IsChallengeRecord(r) {
			out = append(out, r)
		}
	}
	return Describe(out)
}

func (f *fakeDNS) has(zone string, r mijnhost.DNSRecord) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, x := range f.zones[zone] {
		if x == r {
			return true
		}
	}
	return false
}

func txt(name, value string) mijnhost.DNSRecord {
	return mijnhost.DNSRecord{Type: "TXT", Name: name, Value: value, TTL: 300}
}

// fixedClock is a controllable clock for lock and expiry tests.
type fixedClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fixedClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fixedClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
