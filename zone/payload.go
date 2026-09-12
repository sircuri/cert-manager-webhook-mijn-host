// Package zone serializes and reconciles DNS-01 challenge records per zone.
//
// It combines three things:
//   - a per-zone lock backed by a Kubernetes Lease, so only one webhook pod
//     writes a zone at a time (see lock.go);
//   - a per-zone ConfigMap that records which challenge TXT records the
//     webhook currently wants present (see store.go);
//   - a payload rule that turns "what mijn.host returned" plus "what we want"
//     into the full zone to upload (this file).
//
// Together they make the full-zone PUT of the mijn.host API safe even though
// its reads can be stale.
package zone

import (
	"sort"
	"strings"

	"github.com/sircuri/cert-manager-webhook-mijn-host/mijnhost"
)

// ChallengePrefix is the label ACME DNS-01 challenge records live under.
const ChallengePrefix = "_acme-challenge."

// Key identifies a challenge record: absolute name (with trailing dot) plus
// value. Several values can coexist under one name.
type Key struct {
	Name  string
	Value string
}

// IsChallengeRecord reports whether r is an ACME DNS-01 challenge record.
func IsChallengeRecord(r mijnhost.DNSRecord) bool {
	return r.Type == "TXT" && strings.HasPrefix(r.Name, ChallengePrefix)
}

// Diff describes what a PUT changes among the challenge records of a zone.
type Diff struct {
	Add    []mijnhost.DNSRecord
	Remove []mijnhost.DNSRecord
	Kept   int
}

// Changed reports whether a PUT is needed at all.
func (d Diff) Changed() bool { return len(d.Add) > 0 || len(d.Remove) > 0 }

// ComputePayload builds the full record set to upload.
//
// Non-challenge records from api are always passed through untouched.
//
// With ownAll, the challenge records in the result are exactly desired:
// anything else named _acme-challenge.* is dropped. This makes stale reads
// harmless in both directions and removes leftovers from earlier failures.
//
// Without ownAll, challenge records in api are kept unless they are listed in
// remove, and desired records missing from api are added. This preserves
// records of other ACME clients but cannot clean up leftovers, and a stale
// read can resurrect a record that was just removed.
func ComputePayload(api, desired []mijnhost.DNSRecord, remove []Key, ownAll bool) ([]mijnhost.DNSRecord, Diff) {
	desired = dedupe(desired)
	wanted := make(map[Key]mijnhost.DNSRecord, len(desired))
	for _, r := range desired {
		wanted[Key{r.Name, r.Value}] = r
	}
	dropping := make(map[Key]bool, len(remove))
	for _, k := range remove {
		dropping[k] = true
	}

	var diff Diff
	payload := make([]mijnhost.DNSRecord, 0, len(api)+len(desired))
	present := make(map[Key]bool, len(api))

	for _, r := range api {
		if !IsChallengeRecord(r) {
			payload = append(payload, r)
			continue
		}
		k := Key{r.Name, r.Value}
		if present[k] {
			continue // duplicate in API response, collapse it
		}
		present[k] = true
		switch {
		case wanted[k].Name != "":
			payload = append(payload, wanted[k])
			diff.Kept++
		case ownAll || dropping[k]:
			diff.Remove = append(diff.Remove, r)
		default:
			payload = append(payload, r)
			diff.Kept++
		}
	}
	for _, r := range desired {
		if !present[Key{r.Name, r.Value}] {
			payload = append(payload, r)
			diff.Add = append(diff.Add, r)
		}
	}
	return payload, diff
}

func dedupe(records []mijnhost.DNSRecord) []mijnhost.DNSRecord {
	seen := make(map[Key]bool, len(records))
	out := make([]mijnhost.DNSRecord, 0, len(records))
	for _, r := range records {
		k := Key{r.Name, r.Value}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, r)
	}
	return out
}

// Describe renders records as "name=value" strings for log output.
func Describe(records []mijnhost.DNSRecord) []string {
	out := make([]string, 0, len(records))
	for _, r := range records {
		out = append(out, r.Name+"="+r.Value)
	}
	sort.Strings(out)
	return out
}

// AbsoluteName returns the FQDN form (with trailing dot) of name relative to
// zone, matching how the mijn.host API stores names. name may already be
// absolute or relative to the zone, with or without a trailing dot.
func AbsoluteName(name, zone string) string {
	name = strings.TrimSuffix(name, ".")
	zone = strings.TrimSuffix(zone, ".")
	if name == "" || name == "@" {
		return zone + "."
	}
	if name == zone || strings.HasSuffix(name, "."+zone) {
		return name + "."
	}
	return name + "." + zone + "."
}

// ObjectName derives a valid Kubernetes object name for a zone. Used for the
// Lease and the ConfigMap so both can be found from the zone alone.
func ObjectName(zone string) string {
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	var b strings.Builder
	for _, c := range zone {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		} else {
			b.WriteRune('-')
		}
	}
	return "mijn-host-zone-" + strings.Trim(b.String(), "-")
}
