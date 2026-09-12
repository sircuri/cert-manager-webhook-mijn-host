package zone

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

func newTestLock(cs kubernetes.Interface, identity string, clock *fixedClock) *LeaseLock {
	return NewLeaseLock(cs, "cert-manager", identity, LeaseLockOptions{
		Duration:     60 * time.Second,
		WaitTimeout:  2 * time.Second,
		PollInterval: 5 * time.Millisecond,
		Now:          clock.now,
	})
}

func holderOf(t *testing.T, cs kubernetes.Interface, zone string) string {
	t.Helper()
	lease, err := cs.CoordinationV1().Leases("cert-manager").Get(context.Background(), ObjectName(zone), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get lease: %v", err)
	}
	return ptr.Deref(lease.Spec.HolderIdentity, "")
}

func TestLeaseLock_AcquireAndRelease(t *testing.T) {
	cs := newFakeKube()
	clock := &fixedClock{t: time.Now()}
	lock := newTestLock(cs, "pod-a", clock)

	release, err := lock.Acquire(context.Background(), "example.nl")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if h := holderOf(t, cs, "example.nl"); h == "" || h[:6] != "pod-a/" {
		t.Fatalf("holder = %q", h)
	}
	release()
	if h := holderOf(t, cs, "example.nl"); h != "" {
		t.Fatalf("holder after release = %q", h)
	}
}

func TestLeaseLock_SecondAcquirerWaitsForRelease(t *testing.T) {
	cs := newFakeKube()
	clock := &fixedClock{t: time.Now()}
	a := newTestLock(cs, "pod-a", clock)
	b := newTestLock(cs, "pod-b", clock)

	releaseA, err := a.Acquire(context.Background(), "example.nl")
	if err != nil {
		t.Fatalf("acquire a: %v", err)
	}

	var acquiredB atomic.Bool
	done := make(chan error, 1)
	go func() {
		releaseB, err := b.Acquire(context.Background(), "example.nl")
		if err == nil {
			acquiredB.Store(true)
			releaseB()
		}
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if acquiredB.Load() {
		t.Fatal("pod-b acquired the lock while pod-a held it")
	}
	releaseA()
	if err := <-done; err != nil {
		t.Fatalf("acquire b: %v", err)
	}
}

func TestLeaseLock_TimesOutWhileHeld(t *testing.T) {
	cs := newFakeKube()
	clock := &fixedClock{t: time.Now()}
	a := newTestLock(cs, "pod-a", clock)
	b := newTestLock(cs, "pod-b", clock)

	releaseA, err := a.Acquire(context.Background(), "example.nl")
	if err != nil {
		t.Fatalf("acquire a: %v", err)
	}
	defer releaseA()

	// Move the clock past the wait timeout but not past the lease duration.
	go func() {
		time.Sleep(20 * time.Millisecond)
		clock.advance(3 * time.Second)
	}()
	_, err = b.Acquire(context.Background(), "example.nl")
	if !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("expected ErrLockTimeout, got %v", err)
	}
}

func TestLeaseLock_ExpiredLeaseIsTakenOver(t *testing.T) {
	cs := newFakeKube()
	clock := &fixedClock{t: time.Now()}
	a := newTestLock(cs, "pod-a", clock)
	b := newTestLock(cs, "pod-b", clock)

	releaseA, err := a.Acquire(context.Background(), "example.nl")
	if err != nil {
		t.Fatalf("acquire a: %v", err)
	}
	// pod-a "crashes": never releases. Time passes beyond the lease duration.
	clock.advance(61 * time.Second)

	releaseB, err := b.Acquire(context.Background(), "example.nl")
	if err != nil {
		t.Fatalf("acquire b after expiry: %v", err)
	}
	if h := holderOf(t, cs, "example.nl"); h[:6] != "pod-b/" {
		t.Fatalf("holder = %q", h)
	}

	// pod-a's stale release must not clear pod-b's lease.
	releaseA()
	if h := holderOf(t, cs, "example.nl"); h[:6] != "pod-b/" {
		t.Fatalf("stale release cleared the lease, holder = %q", h)
	}
	releaseB()
}

func TestLeaseLock_DifferentZonesDoNotBlockEachOther(t *testing.T) {
	cs := newFakeKube()
	clock := &fixedClock{t: time.Now()}
	lock := newTestLock(cs, "pod-a", clock)

	r1, err := lock.Acquire(context.Background(), "example.nl")
	if err != nil {
		t.Fatalf("acquire zone 1: %v", err)
	}
	defer r1()
	r2, err := lock.Acquire(context.Background(), "other.nl")
	if err != nil {
		t.Fatalf("acquire zone 2: %v", err)
	}
	defer r2()
}

func TestLeaseLock_MutualExclusionUnderContention(t *testing.T) {
	cs := newFakeKube()
	clock := &fixedClock{t: time.Now()}

	var inside int32
	var violations int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			lock := NewLeaseLock(cs, "cert-manager", "pod", LeaseLockOptions{
				Duration: time.Minute, WaitTimeout: 5 * time.Second, PollInterval: time.Millisecond, Now: clock.now,
			})
			for j := 0; j < 5; j++ {
				release, err := lock.Acquire(context.Background(), "example.nl")
				if err != nil {
					t.Errorf("worker %d: %v", i, err)
					return
				}
				if atomic.AddInt32(&inside, 1) != 1 {
					atomic.AddInt32(&violations, 1)
				}
				time.Sleep(time.Millisecond)
				atomic.AddInt32(&inside, -1)
				release()
			}
		}(i)
	}
	wg.Wait()
	if violations != 0 {
		t.Fatalf("%d workers were inside the critical section at the same time", violations)
	}
}

func TestLeaseLock_ContextCancelStopsWaiting(t *testing.T) {
	cs := newFakeKube()
	clock := &fixedClock{t: time.Now()}
	a := newTestLock(cs, "pod-a", clock)
	b := newTestLock(cs, "pod-b", clock)

	releaseA, err := a.Acquire(context.Background(), "example.nl")
	if err != nil {
		t.Fatalf("acquire a: %v", err)
	}
	defer releaseA()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := b.Acquire(ctx, "example.nl"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context error, got %v", err)
	}
}
