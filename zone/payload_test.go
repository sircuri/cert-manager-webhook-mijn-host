package zone

import (
	"testing"

	"github.com/sircuri/cert-manager-webhook-mijn-host/mijnhost"
)

var (
	recA    = mijnhost.DNSRecord{Type: "A", Name: "example.nl.", Value: "1.2.3.4", TTL: 900}
	recMX   = mijnhost.DNSRecord{Type: "MX", Name: "example.nl.", Value: "10 mail.example.nl.", TTL: 900}
	recSPF  = mijnhost.DNSRecord{Type: "TXT", Name: "example.nl.", Value: "v=spf1 -all", TTL: 900}
	recDKIM = mijnhost.DNSRecord{Type: "TXT", Name: "x._domainkey.example.nl.", Value: "v=DKIM1", TTL: 900}
	chalA   = txt("_acme-challenge.example.nl.", "aaa")
	chalB   = txt("_acme-challenge.example.nl.", "bbb")
	chalOld = txt("_acme-challenge.dev.example.nl.", "leftover")
)

func TestIsChallengeRecord(t *testing.T) {
	if !IsChallengeRecord(chalA) {
		t.Error("challenge TXT not recognised")
	}
	for _, r := range []mijnhost.DNSRecord{recA, recSPF, recDKIM, {Type: "CNAME", Name: "_acme-challenge.example.nl.", Value: "x."}} {
		if IsChallengeRecord(r) {
			t.Errorf("%+v wrongly recognised as challenge record", r)
		}
	}
}

func TestComputePayload_PassesNonChallengeRecordsThrough(t *testing.T) {
	api := []mijnhost.DNSRecord{recA, recMX, recSPF, recDKIM}
	payload, diff := ComputePayload(api, []mijnhost.DNSRecord{chalA}, nil, true)

	if !equalStrings(Describe(payload), Describe(append(api, chalA))) {
		t.Fatalf("payload = %v", Describe(payload))
	}
	if len(diff.Add) != 1 || len(diff.Remove) != 0 || !diff.Changed() {
		t.Fatalf("diff = %+v", diff)
	}
}

func TestComputePayload_NoWriteWhenInSync(t *testing.T) {
	api := []mijnhost.DNSRecord{recA, chalA, chalB}
	_, diff := ComputePayload(api, []mijnhost.DNSRecord{chalB, chalA}, nil, true)
	if diff.Changed() {
		t.Fatalf("expected no change, diff = %+v", diff)
	}
	if diff.Kept != 2 {
		t.Errorf("kept = %d", diff.Kept)
	}
}

func TestComputePayload_TTLDifferenceIsNotAChange(t *testing.T) {
	inAPI := chalA
	inAPI.TTL = 600
	_, diff := ComputePayload([]mijnhost.DNSRecord{inAPI}, []mijnhost.DNSRecord{chalA}, nil, true)
	if diff.Changed() {
		t.Fatalf("TTL-only difference should not trigger a write, diff = %+v", diff)
	}
}

func TestComputePayload_StaleReadMissingOurRecordIsRestored(t *testing.T) {
	// API view predates our earlier write of chalA. Desired still lists it.
	api := []mijnhost.DNSRecord{recA}
	payload, diff := ComputePayload(api, []mijnhost.DNSRecord{chalA, chalB}, nil, true)
	if !equalStrings(Describe(payload), Describe([]mijnhost.DNSRecord{recA, chalA, chalB})) {
		t.Fatalf("payload = %v", Describe(payload))
	}
	if len(diff.Add) != 2 {
		t.Fatalf("diff = %+v", diff)
	}
}

func TestComputePayload_StaleReadShowingRemovedRecordDropsIt(t *testing.T) {
	// We removed chalA earlier; the API still shows it. It must not come back.
	api := []mijnhost.DNSRecord{recA, chalA, chalB}
	payload, diff := ComputePayload(api, []mijnhost.DNSRecord{chalB}, nil, true)
	if !equalStrings(Describe(payload), Describe([]mijnhost.DNSRecord{recA, chalB})) {
		t.Fatalf("payload = %v", Describe(payload))
	}
	if len(diff.Remove) != 1 || diff.Remove[0] != chalA {
		t.Fatalf("diff = %+v", diff)
	}
}

func TestComputePayload_OwnAllRemovesLeftovers(t *testing.T) {
	api := []mijnhost.DNSRecord{recA, chalOld}
	payload, diff := ComputePayload(api, nil, nil, true)
	if !equalStrings(Describe(payload), Describe([]mijnhost.DNSRecord{recA})) {
		t.Fatalf("payload = %v", Describe(payload))
	}
	if len(diff.Remove) != 1 {
		t.Fatalf("diff = %+v", diff)
	}
}

func TestComputePayload_NotOwnAllKeepsForeignRecords(t *testing.T) {
	api := []mijnhost.DNSRecord{recA, chalOld}
	payload, diff := ComputePayload(api, []mijnhost.DNSRecord{chalA}, nil, false)
	if !equalStrings(Describe(payload), Describe([]mijnhost.DNSRecord{recA, chalOld, chalA})) {
		t.Fatalf("payload = %v", Describe(payload))
	}
	if len(diff.Remove) != 0 || len(diff.Add) != 1 {
		t.Fatalf("diff = %+v", diff)
	}
}

func TestComputePayload_NotOwnAllStillRemovesExplicitly(t *testing.T) {
	api := []mijnhost.DNSRecord{recA, chalA, chalOld}
	payload, diff := ComputePayload(api, nil, []Key{{chalA.Name, chalA.Value}}, false)
	if !equalStrings(Describe(payload), Describe([]mijnhost.DNSRecord{recA, chalOld})) {
		t.Fatalf("payload = %v", Describe(payload))
	}
	if len(diff.Remove) != 1 || diff.Remove[0] != chalA {
		t.Fatalf("diff = %+v", diff)
	}
}

func TestComputePayload_CollapsesDuplicates(t *testing.T) {
	api := []mijnhost.DNSRecord{chalA, chalA}
	payload, diff := ComputePayload(api, []mijnhost.DNSRecord{chalA, chalA}, nil, true)
	if len(payload) != 1 {
		t.Fatalf("payload = %v", Describe(payload))
	}
	// Collapsing a duplicate is not reported as a change; the next real
	// write fixes it as a side effect.
	if diff.Changed() {
		t.Fatalf("diff = %+v", diff)
	}
}

func TestAbsoluteName(t *testing.T) {
	cases := map[[2]string]string{
		{"_acme-challenge.example.nl", "example.nl"}:   "_acme-challenge.example.nl.",
		{"_acme-challenge.example.nl.", "example.nl."}: "_acme-challenge.example.nl.",
		{"_acme-challenge", "example.nl"}:              "_acme-challenge.example.nl.",
		{"@", "example.nl"}:                            "example.nl.",
		{"example.nl", "example.nl"}:                   "example.nl.",
	}
	for in, want := range cases {
		if got := AbsoluteName(in[0], in[1]); got != want {
			t.Errorf("AbsoluteName(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

func TestObjectName(t *testing.T) {
	if got := ObjectName("Example.NL."); got != "mijn-host-zone-example-nl" {
		t.Errorf("got %q", got)
	}
	if got := ObjectName("xn--caf-dma.nl"); got != "mijn-host-zone-xn--caf-dma-nl" {
		t.Errorf("got %q", got)
	}
}
