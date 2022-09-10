package main

import (
	"github.com/jetstack/cert-manager/test/acme/dns"
	"os"
	"testing"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

func TestRunsSuite(t *testing.T) {
	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.

	solver := &njallaDNSProviderSolver{}
	fixture := dns.NewFixture(solver,
		dns.SetResolvedZone(zone),
		dns.SetAllowAmbientCredentials(false),
		dns.SetManifestPath("testdata/njalla"),
	)

	fixture.RunConformance(t)
}
