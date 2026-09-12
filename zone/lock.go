package zone

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

// ErrLockTimeout is returned when the zone lock could not be acquired within
// the configured wait time. The caller should fail the request; cert-manager
// retries it later.
var ErrLockTimeout = errors.New("timed out waiting for zone lock")

// Locker hands out exclusive access to a zone.
type Locker interface {
	// Acquire blocks until the zone lock is held or ctx or the wait timeout
	// expires. The returned function releases the lock.
	Acquire(ctx context.Context, zone string) (release func(), err error)
}

// LeaseLock implements Locker with one coordination.k8s.io Lease per zone.
//
// Acquire is a compare-and-swap loop: create the Lease if it does not exist
// (fails with AlreadyExists if another pod was first) or update it with our
// identity if it is unheld or expired (fails with Conflict if another pod was
// first). Either failure just retries. A Lease held by a crashed pod is taken
// over once its duration has passed.
type LeaseLock struct {
	client       kubernetes.Interface
	namespace    string
	identity     string
	duration     time.Duration
	waitTimeout  time.Duration
	pollInterval time.Duration
	now          func() time.Time
}

// LeaseLockOptions tunes a LeaseLock. Zero values pick the defaults.
type LeaseLockOptions struct {
	// Duration after which an unreleased lease may be taken over. Default 60s.
	Duration time.Duration
	// WaitTimeout bounds how long Acquire waits. Default 25s.
	WaitTimeout time.Duration
	// PollInterval between attempts while the lease is held. Default 500ms.
	PollInterval time.Duration
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// NewLeaseLock creates a LeaseLock. identity is normally the pod name.
func NewLeaseLock(client kubernetes.Interface, namespace, identity string, opts LeaseLockOptions) *LeaseLock {
	l := &LeaseLock{
		client:       client,
		namespace:    namespace,
		identity:     identity,
		duration:     opts.Duration,
		waitTimeout:  opts.WaitTimeout,
		pollInterval: opts.PollInterval,
		now:          opts.Now,
	}
	if l.duration <= 0 {
		l.duration = 60 * time.Second
	}
	if l.waitTimeout <= 0 {
		l.waitTimeout = 25 * time.Second
	}
	if l.pollInterval <= 0 {
		l.pollInterval = 500 * time.Millisecond
	}
	if l.now == nil {
		l.now = time.Now
	}
	return l
}

// Acquire implements Locker.
func (l *LeaseLock) Acquire(ctx context.Context, zone string) (func(), error) {
	log := logr.FromContextOrDiscard(ctx)
	name := ObjectName(zone)
	holder := l.identity + "/" + randomToken()
	deadline := l.now().Add(l.waitTimeout)
	start := l.now()

	for {
		acquired, heldBy, err := l.tryAcquire(ctx, name, holder)
		if err != nil {
			return nil, fmt.Errorf("acquire lock for zone %s: %w", zone, err)
		}
		if acquired {
			log.Info("zone lock acquired", "zone", zone, "lease", name, "waited", l.now().Sub(start).Round(time.Millisecond))
			return func() { l.release(log, zone, name, holder) }, nil
		}
		if l.now().After(deadline) {
			log.Error(ErrLockTimeout, "zone lock not acquired", "zone", zone, "lease", name, "heldBy", heldBy, "waited", l.now().Sub(start).Round(time.Millisecond))
			return nil, fmt.Errorf("zone %s is locked by %s: %w", zone, heldBy, ErrLockTimeout)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(l.pollInterval):
		}
	}
}

// tryAcquire makes one attempt. It returns acquired=false with the current
// holder when the lease is validly held by someone else, and retries
// internally on the benign create/update races.
func (l *LeaseLock) tryAcquire(ctx context.Context, name, holder string) (acquired bool, heldBy string, err error) {
	leases := l.client.CoordinationV1().Leases(l.namespace)
	now := metav1.NewMicroTime(l.now())
	seconds := ptr.To(int32(l.duration / time.Second))

	lease, err := leases.Get(ctx, name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		_, err = leases.Create(ctx, &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: l.namespace,
				Labels:    map[string]string{managedByLabel: managedByValue},
			},
			Spec: coordinationv1.LeaseSpec{
				HolderIdentity:       ptr.To(holder),
				LeaseDurationSeconds: seconds,
				AcquireTime:          &now,
				RenewTime:            &now,
			},
		}, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			return false, "another pod (creating)", nil
		}
		return err == nil, "", err
	case err != nil:
		return false, "", err
	}

	current := ptr.Deref(lease.Spec.HolderIdentity, "")
	if current != "" && !l.expired(lease) {
		return false, current, nil
	}

	lease.Spec.HolderIdentity = ptr.To(holder)
	lease.Spec.LeaseDurationSeconds = seconds
	lease.Spec.AcquireTime = &now
	lease.Spec.RenewTime = &now
	lease.Spec.LeaseTransitions = ptr.To(ptr.Deref(lease.Spec.LeaseTransitions, 0) + 1)
	_, err = leases.Update(ctx, lease, metav1.UpdateOptions{})
	if apierrors.IsConflict(err) {
		return false, "another pod (updating)", nil
	}
	return err == nil, "", err
}

func (l *LeaseLock) expired(lease *coordinationv1.Lease) bool {
	if lease.Spec.RenewTime == nil || lease.Spec.LeaseDurationSeconds == nil {
		return true
	}
	expiry := lease.Spec.RenewTime.Add(time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second)
	return l.now().After(expiry)
}

// release clears the holder if, and only if, it is still ours. It uses its
// own context because the request context may already be cancelled.
func (l *LeaseLock) release(log logr.Logger, zone, name, holder string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	leases := l.client.CoordinationV1().Leases(l.namespace)

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		lease, err := leases.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			lastErr = err
			continue
		}
		if ptr.Deref(lease.Spec.HolderIdentity, "") != holder {
			return // taken over after expiry, nothing to release
		}
		lease.Spec.HolderIdentity = ptr.To("")
		_, err = leases.Update(ctx, lease, metav1.UpdateOptions{})
		if err == nil {
			log.Info("zone lock released", "zone", zone, "lease", name)
			return
		}
		lastErr = err
		if !apierrors.IsConflict(err) {
			break
		}
	}
	// Not fatal: the lease expires on its own after its duration.
	log.Error(lastErr, "zone lock release failed, lease will expire", "zone", zone, "lease", name)
}

func randomToken() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
