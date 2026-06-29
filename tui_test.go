package main

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
	"time"
	"unicode/utf8"
)

func TestProgressPercent(t *testing.T) {
	if got := progressPercent(0, 100); got != 0 {
		t.Fatalf("0%% got %d", got)
	}
	if got := progressPercent(50, 100); got != 50 {
		t.Fatalf("50%% got %d", got)
	}
	if got := progressPercent(150, 100); got != 100 {
		t.Fatalf("cap at 100 got %d", got)
	}
}

func TestProgressBar(t *testing.T) {
	plain := func(done, total int64, width int) string {
		if total <= 0 {
			return "[" + strings.Repeat("─", width) + "]"
		}
		filled := int(done * int64(width) / total)
		if filled > width {
			filled = width
		}
		return "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + "]"
	}
	if got := plain(0, 100, 10); got != "[░░░░░░░░░░]" {
		t.Fatalf("empty progress = %q", got)
	}
	if got := plain(50, 100, 10); got != "[█████░░░░░]" {
		t.Fatalf("half progress = %q", got)
	}
	if got := plain(100, 100, 10); got != "[██████████]" {
		t.Fatalf("full progress = %q", got)
	}
	if !strings.Contains(progressBar(50, 100, 10), "█") {
		t.Fatal("styled bar should contain fill blocks")
	}
}

func TestFormatScanProgress(t *testing.T) {
	line := formatScanProgress(100, 500, 1000, 8, "scanning", 0, 0)
	if !strings.Contains(line, " 50%") {
		t.Fatalf("missing percent: %q", line)
	}
	if !strings.Contains(line, "500/1000 ports") {
		t.Fatalf("missing port counts: %q", line)
	}
	if !strings.Contains(line, "8 hosts") {
		t.Fatalf("missing host count: %q", line)
	}

	line = formatScanProgress(100, 1000, 1000, 12, "enriching", 45, 12)
	if !strings.Contains(line, "100%") {
		t.Fatalf("enriching should show full ports: %q", line)
	}
	if !strings.Contains(line, "12/45 hosts") {
		t.Fatalf("enriching host progress: %q", line)
	}
}

func TestTrunc(t *testing.T) {
	if trunc("hello", 10) != "hello" {
		t.Fatal("short string unchanged")
	}
	if trunc("hello world", 8) != "hello..." {
		t.Fatalf("got %q", trunc("hello world", 8))
	}
}

func TestParseScanArgsTUI(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"on by default", []string{"192.168.1.0/24"}, true},
		{"--no-tui disables", []string{"192.168.1.0/24", "--no-tui"}, false},
		{"-N alias disables", []string{"192.168.1.0/24", "-N"}, false},
		{"auto-off with --json", []string{"192.168.1.0/24", "--json", "out.json"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseScanArgs(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.TUI != tc.want {
				t.Fatalf("TUI=%v, want %v", cfg.TUI, tc.want)
			}
		})
	}
}

func TestTuiRowColor(t *testing.T) {
	now := time.Now()
	if p, _ := tuiRowColor(hostResult{IP: "192.168.1.10"}, now, nil); p != "" {
		t.Fatalf("expected no full-row color for a steady host, got %q", p)
	}
	if p, _ := tuiRowColor(hostResult{Status: "dead"}, now, nil); p != escRed {
		t.Fatal("expected red for dead regardless of arp")
	}
	changed := map[string]time.Time{"192.168.1.10": now.Add(-200 * time.Millisecond)}
	if p, _ := tuiRowColor(hostResult{IP: "192.168.1.10"}, now, changed); !strings.Contains(p, escReverse) {
		t.Fatalf("expected reverse cue for a recently changed host, got %q", p)
	}
	expired := map[string]time.Time{"192.168.1.10": now.Add(-5 * time.Second)}
	if p, _ := tuiRowColor(hostResult{IP: "192.168.1.10"}, now, expired); p != "" {
		t.Fatalf("expected change cue to expire, got %q", p)
	}
}

func TestTuiStatusGlyph(t *testing.T) {
	now := time.Now()
	discovered := map[string]time.Time{"192.168.1.10": now.Add(-30 * time.Second)}
	if g := tuiStatusGlyph(hostResult{IP: "192.168.1.10"}, "watch", now, discovered, 0); g != "+" {
		t.Fatalf("expected + for new host, got %q", g)
	}
	if g := tuiStatusGlyph(hostResult{Status: "dead"}, "done", now, nil, 5); g != "○" {
		t.Fatalf("expected ○ for down host, got %q", g)
	}
	if g := tuiStatusGlyph(hostResult{LatencyMS: 5}, "done", now, nil, 2); g != "!" {
		t.Fatalf("expected ! for suspect host, got %q", g)
	}
	if g := tuiStatusGlyph(hostResult{LatencyMS: 5}, "done", now, nil, 0); g != "●" {
		t.Fatalf("expected ● for up host, got %q", g)
	}
}

func TestLatencyCellText(t *testing.T) {
	if c := latencyCellText(hostResult{Status: "dead", LatencyMS: -1}, 10); c != "down" {
		t.Fatalf("dead host cell = %q", c)
	}
	if c := latencyCellText(hostResult{LatencyMS: 12}, 1); c != "-" {
		t.Fatalf("suspect host cell = %q", c)
	}
	if c := latencyCellText(hostResult{LatencyMS: -1}, 0); c != "·" {
		t.Fatalf("unknown latency cell = %q", c)
	}
	if c := latencyCellText(hostResult{LatencyMS: 12}, 0); c != "12" {
		t.Fatalf("live latency cell = %q", c)
	}
}

func TestMissColorFades(t *testing.T) {
	// Force the colored branch so the fade logic is covered even under NO_COLOR.
	saved := escRed
	escRed = "\033[31m"
	defer func() { escRed = saved }()

	if got := missColor(0); got != "" {
		t.Fatalf("no color before the first miss, got %q", got)
	}
	first := missColor(1)
	last := missColor(tuiDeadAfterMisses - 1)
	if first == "" || last == "" {
		t.Fatal("expected non-empty miss colors when color is enabled")
	}
	if first == last {
		t.Fatalf("expected miss color to change as misses grow: %q vs %q", first, last)
	}
}

func TestHostPingStatsAvg(t *testing.T) {
	tui := &scanTUI{pingStats: map[string]*hostPingStats{}}
	for _, ms := range []int64{10, 20, 30, 40, 50, 60, 70} {
		tui.recordPingLocked("10.0.0.1", ms)
	}
	s := tui.pingStats["10.0.0.1"]
	if len(s.samples) != tuiPingAvgWindow {
		t.Fatalf("expected %d samples, got %d", tuiPingAvgWindow, len(s.samples))
	}
	// Moving average of the last 6 samples: 20..70 -> 45.
	if got := s.avg(); got != 45 {
		t.Fatalf("avg = %d, want 45", got)
	}
	// min/max are cumulative across all observed pings, so the evicted 10 remains.
	if s.min != 10 || s.max != 70 {
		t.Fatalf("min/max = %d/%d, want 10/70", s.min, s.max)
	}
	if n := tui.recordMissLocked("10.0.0.1"); n != 1 {
		t.Fatalf("first miss = %d, want 1", n)
	}
	tui.recordPingLocked("10.0.0.1", 25)
	if tui.missesLocked("10.0.0.1") != 0 {
		t.Fatal("a successful ping should reset the miss counter")
	}
}

func TestTuiLatencyColor(t *testing.T) {
	cases := []struct {
		host hostResult
		want string
	}{
		{hostResult{LatencyMS: 10}, escBrightGreen},
		{hostResult{LatencyMS: 100}, escGreen},
		{hostResult{LatencyMS: 300}, escYellow},
		{hostResult{LatencyMS: 500}, escRed},
		{hostResult{LatencyMS: -1}, escDim},
		{hostResult{Status: "dead", LatencyMS: -1}, escRed},
	}
	for _, c := range cases {
		if got := tuiLatencyColor(c.host); got != c.want {
			t.Fatalf("tuiLatencyColor(%+v) = %q want %q", c.host, got, c.want)
		}
	}
}

func TestPadRight(t *testing.T) {
	if got := padRight("·", 3); got != "·  " {
		t.Fatalf("multibyte pad = %q", got)
	}
	if got := padRight("ab", 1); got != "ab" {
		t.Fatalf("overflow should not truncate: %q", got)
	}
}

func TestTuiDoneLayout(t *testing.T) {
	lay := tuiDoneLayout(120, false)
	if lay.ports != tuiPortsWidth {
		t.Fatalf("ports width = %d, want %d", lay.ports, tuiPortsWidth)
	}
	if lay.vendor != tuiVendorWidth || lay.name != tuiNameWidth {
		t.Fatalf("vendor/name widths wrong: %+v", lay)
	}
	if lay.st != 1 || lay.ip != 15 || lay.mac != 17 || lay.ms != 4 {
		t.Fatalf("fixed columns wrong: %+v", lay)
	}
	if lay.lmin != 3 || lay.lmax != 3 || lay.lavg != 3 {
		t.Fatalf("min/max/avg columns wrong: %+v", lay)
	}
	if lay.arpState != 0 || lay.arpAlias != 0 || lay.arpIndex != 0 {
		t.Fatalf("arp columns should be hidden by default: %+v", lay)
	}
	layARP := tuiDoneLayout(120, true)
	if layARP.arpState != 11 || layARP.arpAlias != 14 || layARP.arpIndex != 5 {
		t.Fatalf("arp columns wrong with --arp-detail: %+v", layARP)
	}
}

func TestTuiPortsCellTruncates(t *testing.T) {
	var ports []portResult
	for p := 20; p <= 120; p++ {
		ports = append(ports, portResult{Port: p})
	}
	got := tuiPortsCell(hostResult{OpenPorts: ports}, tuiPortsWidth)
	if utf8.RuneCountInString(strings.TrimSpace(got)) > tuiPortsWidth {
		t.Fatalf("ports cell wider than %d: %q", tuiPortsWidth, got)
	}
	if !strings.Contains(got, "...") {
		t.Fatalf("expected truncated ports: %q", got)
	}
}

func TestFormatTuiNameDisplay(t *testing.T) {
	long := strings.Repeat("x", 40)
	got := formatTuiNameDisplay(long)
	if len(got) != tuiNameWidth {
		t.Fatalf("len=%d want %d: %q", len(got), tuiNameWidth, got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("expected ellipsis truncation: %q", got)
	}
}

func TestToggleAutoPing(t *testing.T) {
	tui := &scanTUI{autoPing: true}
	tui.toggleAutoPing()
	if tui.autoPing {
		t.Fatal("expected auto-ping off")
	}
	if tui.exportStatus != "auto-ping off" {
		t.Fatalf("status=%q", tui.exportStatus)
	}
}

func TestToggleAutoScan(t *testing.T) {
	tui := &scanTUI{}
	tui.toggleAutoScan()
	if !tui.autoScan {
		t.Fatal("expected auto-scan on")
	}
}

func TestExportResults(t *testing.T) {
	t.Chdir(t.TempDir())
	tui := &scanTUI{
		target:  "192.168.1.0/24",
		phase:   "done",
		elapsed: 2 * time.Second,
		hosts: []hostResult{
			{IP: "192.168.1.5", LatencyMS: 10, Status: "live", OpenPorts: []portResult{{Port: 80, Service: "http"}}},
			{IP: "192.168.1.2", LatencyMS: -1, Status: "dead"},
		},
	}
	tui.watch = tuiWatchConfig{
		ports:       []int{80},
		timeout:     time.Second,
		concurrency: 16,
		macFormat:   "colon",
		started:     time.Now(),
	}

	checks := map[string][]string{
		"csv":  {"ip,mac,mac_vendor,latency_ms", "192.168.1.2", "192.168.1.5"},
		"json": {"\"hosts\"", "192.168.1.5", "\"target\": \"192.168.1.0/24\""},
		"txt":  {"IP", "192.168.1.2", "192.168.1.5"},
	}
	for format, wants := range checks {
		path, err := tui.exportResults(format)
		if err != nil {
			t.Fatalf("export %s: %v", format, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", format, err)
		}
		if len(data) == 0 {
			t.Fatalf("export %s produced empty file", format)
		}
		body := string(data)
		for _, want := range wants {
			if !strings.Contains(body, want) {
				t.Fatalf("export %s missing %q in:\n%s", format, want, body)
			}
		}
		if strings.ContainsRune(body, '\x1b') {
			t.Fatalf("export %s should be ANSI-free", format)
		}
		if !strings.HasPrefix(filepath.Base(path), "ipscry-export-") || !strings.HasSuffix(path, "."+format) {
			t.Fatalf("unexpected export path %q", path)
		}
	}
}

func TestExportRequiresResultsPhase(t *testing.T) {
	tui := &scanTUI{phase: "scanning"}
	if _, err := tui.exportResults("csv"); err == nil {
		t.Fatal("expected error exporting during scanning phase")
	}
}

func TestHostRowPending(t *testing.T) {
	if !hostRowPending(hostResult{IP: "10.0.0.1", LatencyMS: 5}) {
		t.Fatal("port-open placeholder should be pending")
	}
	if hostRowPending(hostResult{IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:ff", Guess: "windows"}) {
		t.Fatal("enriched host should not be pending")
	}
}

func TestHostReadyReplacesPlaceholder(t *testing.T) {
	tui := &scanTUI{out: io.Discard, pingStats: map[string]*hostPingStats{}}
	tui.upsertPlaceholderLocked("10.0.0.5", 12)
	tui.HostReady(hostResult{IP: "10.0.0.5", MAC: "aa:bb:cc:dd:ee:ff", LatencyMS: 12, Guess: "windows"})
	if len(tui.hosts) != 1 {
		t.Fatalf("hosts=%d, want 1", len(tui.hosts))
	}
	if tui.hosts[0].MAC == "" || hostRowPending(tui.hosts[0]) {
		t.Fatalf("placeholder not replaced: %+v", tui.hosts[0])
	}
}

func TestCycleMacFormat(t *testing.T) {
	if got := cycleMacFormat("colon"); got != "dash" {
		t.Fatalf("colon -> %q", got)
	}
	if got := cycleMacFormat("dash"); got != "none" {
		t.Fatalf("dash -> %q", got)
	}
	if got := cycleMacFormat("none"); got != "colon" {
		t.Fatalf("none -> %q", got)
	}
	if got := cycleMacFormat(""); got != "dash" {
		t.Fatalf("empty -> %q", got)
	}
}

func TestCycleMacFormatHotkey(t *testing.T) {
	tui := &scanTUI{
		out:   io.Discard,
		watch: tuiWatchConfig{macFormat: "colon"},
	}
	tui.cycleMacFormat()
	if tui.watch.macFormat != "dash" {
		t.Fatalf("macFormat=%q, want dash", tui.watch.macFormat)
	}
}

func TestTriggerRescanIgnoresWhenBusy(t *testing.T) {
	tui := &scanTUI{
		out:   io.Discard,
		phase: "scanning",
		watch: tuiWatchConfig{ips: []string{"10.0.0.1"}, ports: []int{80}},
	}
	tui.triggerRescan(context.Background())
	if tui.rescanning {
		t.Fatal("should not start rescan while already scanning")
	}
}

func TestReadKey(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(
		"mrcqps\x1b[A\x1b[B\x1b[5~\x1b[6~\x1b[H\x1b[F\x1bOAk \x1b[1;5A\x1b[3~"))
	want := []tuiKey{
		keyMacFormat, keyRescan, keyCSV, keyExit, keyAutoPing, keyAutoScan, keyUp, keyDown, keyPageUp, keyPageDown, keyTop, keyBottom,
		keyUp, keyUp, keyPageDown, keyTop, keyNone,
	}
	for i, w := range want {
		got, err := readKey(r)
		if err != nil {
			t.Fatalf("readKey[%d]: %v", i, err)
		}
		if got != w {
			t.Fatalf("readKey[%d] = %d want %d", i, got, w)
		}
	}
}

// TestReadKeyByteAtATime simulates a slow/remote terminal that delivers each
// byte of an escape sequence in a separate read; arrow keys must still decode.
func TestReadKeyByteAtATime(t *testing.T) {
	r := bufio.NewReader(iotest.OneByteReader(strings.NewReader("\x1b[A\x1b[6~")))
	for i, w := range []tuiKey{keyUp, keyPageDown} {
		got, err := readKey(r)
		if err != nil {
			t.Fatalf("readKey[%d]: %v", i, err)
		}
		if got != w {
			t.Fatalf("readKey[%d] = %d want %d", i, got, w)
		}
	}
}

func TestScrollClamp(t *testing.T) {
	tui := &scanTUI{out: io.Discard} // non-File writer => 80x24, maxRows = 17
	for i := 0; i < 30; i++ {
		tui.hosts = append(tui.hosts, hostResult{IP: "10.0.0." + strconv.Itoa(i)})
	}
	maxOff := 30 - tuiMaxHostRows(24) // 13

	tui.scroll(keyUp)
	if tui.scrollOff != 0 {
		t.Fatalf("scroll up at top should stay 0, got %d", tui.scrollOff)
	}
	tui.scroll(keyBottom)
	if tui.scrollOff != maxOff {
		t.Fatalf("End should clamp to %d, got %d", maxOff, tui.scrollOff)
	}
	tui.scroll(keyPageDown)
	if tui.scrollOff != maxOff {
		t.Fatalf("page down past end should stay %d, got %d", maxOff, tui.scrollOff)
	}
	tui.scroll(keyTop)
	if tui.scrollOff != 0 {
		t.Fatalf("Home should reset to 0, got %d", tui.scrollOff)
	}
}

func TestSortedKeysByIP(t *testing.T) {
	m := map[string]int{"192.168.1.10": 1, "192.168.1.2": 2, "192.168.1.1": 1}
	got := sortedKeys(m)
	want := []string{"192.168.1.1", "192.168.1.2", "192.168.1.10"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sortedKeys[%d]=%q want %q", i, got[i], want[i])
		}
	}
}
