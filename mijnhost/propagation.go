package mijnhost

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Propagator waits for a DNS TXT record to be visible at every authoritative
// nameserver for a zone. The mijn.host API uses a full-zone PUT and its
// authoritative DNS edge is eventually consistent, so the API returning 200
// does not guarantee that a recursive resolver (or Let's Encrypt's validators)
// will see the new record yet. The webhook must close that gap before
// returning success to cert-manager.
type Propagator interface {
	WaitForTXT(ctx context.Context, zone, fqdn, value string) error
}

// dnsPropagator polls authoritative NS for the zone via direct DNS queries
// (no recursion) until every NS returns the expected TXT value, or until ctx
// is cancelled.
type dnsPropagator struct {
	pollInterval time.Duration
	queryTimeout time.Duration
	resolver     *net.Resolver
}

// NewDNSPropagator returns a Propagator backed by the miekg/dns client.
// pollInterval is the wait between full sweeps of the NS set; queryTimeout
// caps each individual query against a single NS.
func NewDNSPropagator(pollInterval, queryTimeout time.Duration) Propagator {
	return &dnsPropagator{
		pollInterval: pollInterval,
		queryTimeout: queryTimeout,
		resolver:     net.DefaultResolver,
	}
}

func (p *dnsPropagator) WaitForTXT(ctx context.Context, zone, fqdn, value string) error {
	zone = strings.TrimSuffix(zone, ".")
	fqdnDot := dns.Fqdn(fqdn)

	servers, err := p.lookupNSServers(ctx, zone)
	if err != nil {
		return fmt.Errorf("lookup NS for %s: %w", zone, err)
	}
	if len(servers) == 0 {
		return fmt.Errorf("no authoritative NS found for %s", zone)
	}

	var missing []string
	var lastErr error
	for {
		missing, lastErr = p.sweep(ctx, servers, fqdnDot, value)
		if lastErr == nil && len(missing) == 0 {
			return nil
		}

		select {
		case <-ctx.Done():
			if len(missing) > 0 {
				return fmt.Errorf("propagation timeout: value not visible at %d/%d NS (%v): %w",
					len(missing), len(servers), missing, ctx.Err())
			}
			return fmt.Errorf("propagation check error: %w (ctx: %w)", lastErr, ctx.Err())
		case <-time.After(p.pollInterval):
		}
	}
}

// lookupNSServers resolves the authoritative NS hostnames for zone to
// host:port targets reachable for direct DNS queries.
func (p *dnsPropagator) lookupNSServers(ctx context.Context, zone string) ([]string, error) {
	nsRecords, err := p.resolver.LookupNS(ctx, zone)
	if err != nil {
		return nil, err
	}

	var servers []string
	var lastErr error
	for _, ns := range nsRecords {
		host := strings.TrimSuffix(ns.Host, ".")
		ips, err := p.resolver.LookupIP(ctx, "ip", host)
		if err != nil {
			lastErr = err
			continue
		}
		for _, ip := range ips {
			servers = append(servers, net.JoinHostPort(ip.String(), "53"))
		}
	}
	if len(servers) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return servers, nil
}

// sweep queries every NS once and returns the subset that did not return the
// expected value (either because the value was missing or the query failed).
func (p *dnsPropagator) sweep(ctx context.Context, servers []string, fqdn, value string) ([]string, error) {
	var missing []string
	var errs []error

	cl := &dns.Client{Timeout: p.queryTimeout}
	for _, srv := range servers {
		ok, err := p.queryOne(ctx, cl, srv, fqdn, value)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", srv, err))
			missing = append(missing, srv)
			continue
		}
		if !ok {
			missing = append(missing, srv)
		}
	}
	if len(errs) > 0 {
		return missing, errors.Join(errs...)
	}
	return missing, nil
}

// queryOne issues a non-recursive TXT query directly at server and returns
// true iff the response contains a TXT RR matching the expected value.
func (p *dnsPropagator) queryOne(ctx context.Context, cl *dns.Client, server, fqdn, value string) (bool, error) {
	m := new(dns.Msg)
	m.SetQuestion(fqdn, dns.TypeTXT)
	m.RecursionDesired = false

	resp, _, err := cl.ExchangeContext(ctx, m, server)
	if err != nil {
		return false, err
	}
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return false, fmt.Errorf("dns rcode %s", dns.RcodeToString[resp.Rcode])
	}

	for _, rr := range resp.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		for _, t := range txt.Txt {
			if t == value {
				return true, nil
			}
		}
	}
	return false, nil
}
