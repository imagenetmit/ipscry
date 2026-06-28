//go:build windows

package main

import (
	"net"
	"strings"
	"testing"
)

func TestArpCacheEntriesParse(t *testing.T) {
	entries := arpCacheEntries()
	t.Logf("arp cache entries: %d", len(entries))
	for _, e := range entries {
		if net.ParseIP(e.IP) == nil {
			t.Fatalf("invalid IP %q", e.IP)
		}
		if e.IP == "0.0.0.0" || strings.HasPrefix(e.IP, "0.") {
			t.Fatalf("bogus IP %q (struct layout likely wrong)", e.IP)
		}
		if e.MAC == "" {
			t.Fatalf("empty MAC for IP %q", e.IP)
		}
		if e.IfIndex == 0 {
			t.Fatalf("missing ifIndex for IP %q", e.IP)
		}
	}
}
