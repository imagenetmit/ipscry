package main

import (
	"strings"
	"testing"
)

func TestServiceLabel(t *testing.T) {
	if got := serviceLabel(80); got != "http" {
		t.Fatalf("serviceLabel(80)=%q, want http", got)
	}
	if got := serviceLabel(3389); got != "rdp" {
		t.Fatalf("serviceLabel(3389)=%q, want rdp", got)
	}
	if got := serviceLabel(99999); got != "unknown" {
		t.Fatalf("serviceLabel(99999)=%q, want unknown", got)
	}
}

func TestPortVendors(t *testing.T) {
	got := portVendors(443)
	if got == "" {
		t.Fatal("portVendors(443) should be non-empty")
	}
	if !strings.Contains(strings.ToLower(got), "nginx") || !strings.Contains(strings.ToLower(got), "apache") {
		t.Fatalf("portVendors(443)=%q, expected common HTTPS vendors", got)
	}
	if portVendors(99999) != "" {
		t.Fatal("portVendors(99999) should be empty")
	}
}

func TestMACVendor(t *testing.T) {
	if got := macVendor("00:00:0C:AA:BB:CC"); got != "Cisco Systems, Inc" {
		t.Fatalf("macVendor(Cisco OUI)=%q, want Cisco Systems, Inc", got)
	}
	if got := macVendor("de:ad:be:ef:00:01"); got != "" {
		t.Fatalf("unknown MAC should yield empty, got %q", got)
	}
}

func TestMacHexDigits(t *testing.T) {
	cases := map[string]string{
		"aa:bb:cc:dd:ee:ff": "AABBCCDDEEFF",
		"AA-BB-CC-DD-EE-FF": "AABBCCDDEEFF",
		"aabb.ccdd.eeff":    "AABBCCDDEEFF",
		"aa:bb":             "AABB",
		"":                  "",
	}
	for in, want := range cases {
		if got := macHexDigits(in); got != want {
			t.Fatalf("macHexDigits(%q)=%q, want %q", in, got, want)
		}
	}
}
