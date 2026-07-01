package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			// skip ESC [ ... letter
			i++
			for i < len(s) && (s[i] < 0x40 || s[i] > 0x7e) {
				i++
			}
			// i now at final byte; skip it
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func TestRenderDbg(t *testing.T) {
	var buf bytes.Buffer
	tui := &scanTUI{
		out:              &buf,
		phase:            "watch",
		pingStats:        map[string]*hostPingStats{},
		hostDiscoveredAt: map[string]time.Time{},
		hostChangedAt:    map[string]time.Time{},
		watch: tuiWatchConfig{
			macFormat: "colon",
			enrich:    enrichConfig{},
		},
		hosts: []hostResult{
			{IP: "10.10.5.1", MAC: "aa:bb:cc:dd:ee:ff", MACVendor: "Cisco Meraki", LatencyMS: 3, Hostname: "itgdc2.tes.local", Guess: "network", OpenPorts: []portResult{{Port: 80, Service: "http"}}},
			{IP: "10.10.5.20", MAC: "11:22:33:44:55:66", MACVendor: "QSC LLC", LatencyMS: 8, Hostname: "", Guess: "linux/device", OpenPorts: []portResult{{Port: 80, Service: "http", HTTPStatus: "200 OK", HTTPTitle: "Panel"}, {Port: 443, Service: "https"}}},
			{IP: "10.10.5.40", LatencyMS: -1, Status: "dead", Guess: "unknown"},
		},
	}
	// trigger reverse-video highlight on one row, as the deep probe does
	tui.hostChangedAt["10.10.5.20"] = time.Now()
	for _, h := range tui.hosts {
		if h.LatencyMS >= 0 {
			tui.recordPingLocked(h.IP, h.LatencyMS)
		}
	}
	tui.draw()

	clean := stripANSI(buf.String())
	for i, line := range strings.Split(clean, "\n") {
		fmt.Printf("[%2d] |%s|\n", i, line)
	}
}
