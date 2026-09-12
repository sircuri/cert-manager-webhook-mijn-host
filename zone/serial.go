package zone

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ErrSerialUnavailable is reported by a SerialReader when no authoritative
// nameserver answered. The reconciler then skips the serial check (best
// effort) or fails the request (required), depending on configuration.
var ErrSerialUnavailable = errors.New("zone serial unavailable: no authoritative nameserver answered")

// SerialReader returns the SOA serial of a zone: DNS's own version number,
// which the mijn.host API bumps on every write. It is the only modification
// indicator mijn.host exposes; the HTTP API itself has no ETag or version.
type SerialReader interface {
	Serial(ctx context.Context, zone string) (uint32, error)
}

// DNSSerialReader queries the zone's authoritative nameservers for the SOA
// record and returns the highest serial any of them reports. Nameservers
// are discovered through the system resolver and cached per zone.
type DNSSerialReader struct {
	timeout   time.Duration
	lookupNS  func(ctx context.Context, zone string) ([]string, error)
	exchange  func(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error)
	mu        sync.Mutex // guards nsCache and nsCacheAt; requests for different zones run in parallel
	nsCache   map[string][]string
	nsCacheAt map[string]time.Time
	now       func() time.Time
}

// NewDNSSerialReader creates a reader with a per-query timeout.
func NewDNSSerialReader(timeout time.Duration) *DNSSerialReader {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	client := &dns.Client{Timeout: timeout}
	return &DNSSerialReader{
		timeout: timeout,
		lookupNS: func(ctx context.Context, zone string) ([]string, error) {
			nss, err := net.DefaultResolver.LookupNS(ctx, zone)
			if err != nil {
				return nil, err
			}
			out := make([]string, 0, len(nss))
			for _, ns := range nss {
				out = append(out, strings.TrimSuffix(ns.Host, "."))
			}
			return out, nil
		},
		exchange: func(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error) {
			r, _, err := client.ExchangeContext(ctx, m, addr)
			return r, err
		},
		nsCache:   map[string][]string{},
		nsCacheAt: map[string]time.Time{},
		now:       time.Now,
	}
}

const nsCacheTTL = time.Hour

// Serial implements SerialReader.
func (r *DNSSerialReader) Serial(ctx context.Context, zone string) (uint32, error) {
	zone = strings.TrimSuffix(zone, ".")
	servers, err := r.nameservers(ctx, zone)
	if err != nil {
		return 0, fmt.Errorf("%w: lookup NS for %s: %v", ErrSerialUnavailable, zone, err)
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	var best uint32
	answered := 0
	var lastErr error
	for _, ns := range servers {
		qctx, cancel := context.WithTimeout(ctx, r.timeout)
		resp, err := r.exchange(qctx, msg, net.JoinHostPort(ns, "53"))
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		for _, rr := range resp.Answer {
			if soa, ok := rr.(*dns.SOA); ok {
				answered++
				if soa.Serial > best {
					best = soa.Serial
				}
			}
		}
	}
	if answered == 0 {
		if lastErr != nil {
			return 0, fmt.Errorf("%w: %v", ErrSerialUnavailable, lastErr)
		}
		return 0, ErrSerialUnavailable
	}
	return best, nil
}

func (r *DNSSerialReader) nameservers(ctx context.Context, zone string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if at, ok := r.nsCacheAt[zone]; ok && r.now().Sub(at) < nsCacheTTL {
		return r.nsCache[zone], nil
	}
	servers, err := r.lookupNS(ctx, zone)
	if err != nil {
		if cached, ok := r.nsCache[zone]; ok {
			return cached, nil
		}
		return nil, err
	}
	if len(servers) == 0 {
		return nil, errors.New("no NS records")
	}
	r.nsCache[zone] = servers
	r.nsCacheAt[zone] = r.now()
	return servers, nil
}
