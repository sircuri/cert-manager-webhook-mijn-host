package main

import (
	"os"
	"testing"

	dns "github.com/cert-manager/cert-manager/test/acme"
)

func TestConformance(t *testing.T) {
	zone := os.Getenv("TEST_ZONE_NAME")
	if zone == "" {
		t.Skip("TEST_ZONE_NAME not set, skipping conformance tests")
	}

	fixture := dns.NewFixture(&mijnHostSolver{},
		dns.SetResolvedZone(zone),
		dns.SetAllowAmbientCredentials(false),
		dns.SetManifestPath("testdata/mijn-host"),
	)
	fixture.RunConformance(t)
}
