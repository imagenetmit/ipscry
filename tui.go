package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	tuiWatchInterval        = 5 * time.Second
	tuiAutoScanInterval     = 3 * time.Minute
	tuiFastWatchInterval    = 1 * time.Second
	tuiWatchPingConcurrency = 128
	tuiWatchDiscoverWorkers = 4
	tuiNewHostHighlight     = 60 * time.Second
	tuiChangeHighlight      = 1500 * time.Millisecond
	tuiExportStatusTTL      = 4 * time.Second
	tuiDeadAfterMisses      = 10
	tuiPingAvgWindow        = 6
	tuiNameWidth            = 22
	tuiVendorWidth          = 14
	tuiPortsWidth           = 27
)

var spinnerFrames = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

// hostPingStats tracks watch-phase latency history and miss escalation for one
// host. A responsive host has misses==0; after the first missed ping the host is
// "suspect" and is probed at the faster tuiFastWatchInterval until it either
// replies (misses reset to 0) or reaches tuiDeadAfterMisses and is marked dead.
type hostPingStats struct {
	samples []int64 // last up to tuiPingAvgWindow successful latencies (ms)
	min     int64   // -1 until the first successful ping
	max     int64   // -1 until the first successful ping
	misses  int     // consecutive missed pings; 0 when responsive
}

func (s *hostPingStats) avg() int64 {
	if len(s.samples) == 0 {
		return -1
	}
	var sum int64
	for _, v := range s.samples {
		sum += v
	}
	return sum / int64(len(s.samples))
}

// hostPingView is an immutable per-host snapshot of stats for rendering.
type hostPingView struct {
	misses        int
	min, max, avg int64
}

// missRedRamp is a dark→bright pure-red 256-color ramp; a host's ms cell fades
// through it as consecutive misses accumulate (see missColor).
var missRedRamp = []int{52, 88, 124, 160, 196}

type tuiWatchConfig struct {
	ips         []string
	ports       []int
	timeout     time.Duration
	concurrency int
	enrich      enrichConfig
	logger      *log.Logger
	macFormat   string
	started     time.Time
}

type scanMonitor interface {
	Start(target string, totalPorts int64, enrich enrichConfig)
	PortProgress(scanned, total int64)
	PortOpen(ip string, latencyMS int64)
	EnrichStart(ips []string, enrich enrichConfig)
	HostReady(host hostResult)
	Finish(hosts []hostResult, elapsed time.Duration, ctx context.Context, watch tuiWatchConfig)
	Close()
}

type scanTUI struct {
	out              io.Writer
	mu               sync.Mutex
	target           string
	total            atomic.Int64
	scanned          atomic.Int64
	scanHosts        map[string]int64
	hosts            []hostResult
	hostDiscoveredAt map[string]time.Time
	hostChangedAt    map[string]time.Time
	pingStats        map[string]*hostPingStats
	watchPopulated   bool
	frame            atomic.Int64
	scrollOff        int
	exportStatus     string
	exportErr        bool
	exportStatusAt   time.Time
	phase            string
	hostTotal        int
	elapsed          time.Duration
	watch            tuiWatchConfig
	ipChunks         [][]string
	smallNet         bool
	pingChunk        int
	watchChunkNum    int
	watchChunkTotal  int
	pendingDiscover  sync.Map
	discoverSem      chan struct{}
	rescanning       bool
	autoPing         bool
	autoScan         bool
	done             chan struct{}
	pulse            chan struct{}
	once             sync.Once
}

func newScanTUI(out io.Writer) (*scanTUI, error) {
	f, ok := out.(*os.File)
	if !ok || !isTerminal(f) {
		return nil, fmt.Errorf("--tui requires an interactive terminal")
	}
	if err := enableVTMode(f); err != nil {
		return nil, fmt.Errorf("enable terminal colors: %w", err)
	}
	t := &scanTUI{
		out:              out,
		scanHosts:        map[string]int64{},
		hostDiscoveredAt: map[string]time.Time{},
		hostChangedAt:    map[string]time.Time{},
		pingStats:        map[string]*hostPingStats{},
		phase:            "scanning",
		done:             make(chan struct{}),
		pulse:            make(chan struct{}, 1),
		discoverSem:      make(chan struct{}, tuiWatchDiscoverWorkers),
	}
	fmt.Fprint(out, escAltScreen, escHideCursor, escClear, escHome)
	go t.loop()
	return t, nil
}

func (t *scanTUI) loop() {
	ticker := timeNewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			t.draw()
		case <-t.pulse:
			t.draw()
		}
	}
}

func (t *scanTUI) scheduleDraw() {
	select {
	case t.pulse <- struct{}{}:
	default:
	}
}

func (t *scanTUI) Start(target string, totalPorts int64, enrich enrichConfig) {
	t.mu.Lock()
	t.target = target
	t.watch.enrich = enrich
	t.mu.Unlock()
	t.total.Store(totalPorts)
	t.scheduleDraw()
}

func (t *scanTUI) PortProgress(scanned, total int64) {
	t.scanned.Store(scanned)
	if total > 0 {
		t.total.Store(total)
	}
}

func (t *scanTUI) PortOpen(ip string, latencyMS int64) {
	t.mu.Lock()
	if prev, ok := t.scanHosts[ip]; !ok || latencyMS < prev {
		t.scanHosts[ip] = latencyMS
		latencyMS = t.scanHosts[ip]
	} else {
		latencyMS = prev
	}
	t.upsertPlaceholderLocked(ip, latencyMS)
	t.mu.Unlock()
	t.scheduleDraw()
}

func (t *scanTUI) EnrichStart(ips []string, enrich enrichConfig) {
	t.mu.Lock()
	t.phase = "enriching"
	t.hostTotal = len(ips)
	t.watch.enrich = enrich
	for _, ip := range ips {
		ms := int64(-1)
		if v, ok := t.scanHosts[ip]; ok {
			ms = v
		}
		t.upsertPlaceholderLocked(ip, ms)
	}
	t.mu.Unlock()
	t.scheduleDraw()
}

func (t *scanTUI) HostReady(host hostResult) {
	t.mu.Lock()
	for i := range t.hosts {
		if t.hosts[i].IP == host.IP {
			t.hosts[i] = host
			if host.LatencyMS >= 0 {
				t.recordPingLocked(host.IP, host.LatencyMS)
			}
			t.mu.Unlock()
			t.scheduleDraw()
			return
		}
	}
	t.hosts = append(t.hosts, host)
	sort.Slice(t.hosts, func(i, j int) bool { return lessIP(t.hosts[i].IP, t.hosts[j].IP) })
	if host.LatencyMS >= 0 {
		t.recordPingLocked(host.IP, host.LatencyMS)
	}
	t.mu.Unlock()
	t.scheduleDraw()
}

func (t *scanTUI) upsertPlaceholderLocked(ip string, latencyMS int64) {
	for i := range t.hosts {
		if t.hosts[i].IP != ip {
			continue
		}
		if latencyMS >= 0 && (t.hosts[i].LatencyMS < 0 || latencyMS < t.hosts[i].LatencyMS) {
			t.hosts[i].LatencyMS = latencyMS
		}
		return
	}
	t.hosts = append(t.hosts, hostResult{IP: ip, LatencyMS: latencyMS})
	sort.Slice(t.hosts, func(i, j int) bool { return lessIP(t.hosts[i].IP, t.hosts[j].IP) })
}

func hostRowPending(host hostResult) bool {
	return host.MAC == "" && host.Hostname == "" && host.Guess == "" &&
		host.MACVendor == "" && len(host.OpenPorts) == 0
}

func (t *scanTUI) Finish(hosts []hostResult, elapsed time.Duration, ctx context.Context, watch tuiWatchConfig) {
	chunks := splitIPChunks(watch.ips, tuiWatchChunkSize)
	t.mu.Lock()
	t.phase = "watch"
	t.elapsed = elapsed
	t.watch = watch
	t.ipChunks = chunks
	t.smallNet = len(watch.ips) <= tuiWatchChunkSize
	t.pingChunk = 0
	if t.smallNet {
		t.watchChunkNum = 1
		t.watchChunkTotal = 1
	} else {
		t.watchChunkTotal = len(chunks)
		t.watchChunkNum = 1
	}
	t.hosts = append([]hostResult(nil), hosts...)
	sort.Slice(t.hosts, func(i, j int) bool { return lessIP(t.hosts[i].IP, t.hosts[j].IP) })
	t.autoPing = true
	t.autoScan = false
	for i := range t.hosts {
		if t.hosts[i].LatencyMS >= 0 {
			t.recordPingLocked(t.hosts[i].IP, t.hosts[i].LatencyMS)
		}
	}
	t.mu.Unlock()
	t.draw()
	go t.watchLoop(ctx)
	go t.watchScanLoop(ctx)
	go t.fastLoop(ctx)
}

func (t *scanTUI) watchScanLoop(ctx context.Context) {
	ticker := time.NewTicker(tuiAutoScanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.mu.Lock()
			enabled := t.autoScan
			t.mu.Unlock()
			if enabled {
				t.triggerRescan(ctx)
			}
		}
	}
}

func (t *scanTUI) watchLoop(ctx context.Context) {
	t.maybeRunPingTick(ctx)
	ticker := time.NewTicker(tuiWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.maybeRunPingTick(ctx)
		}
	}
}

func (t *scanTUI) maybeRunPingTick(ctx context.Context) {
	t.mu.Lock()
	enabled := t.autoPing
	t.mu.Unlock()
	if enabled {
		t.runPingTick(ctx)
	}
}

// fastLoop probes suspect hosts (those with at least one recent miss) once per
// second so a host that stops responding escalates quickly to dead, while
// healthy hosts stay on the relaxed 5s sweep.
func (t *scanTUI) fastLoop(ctx context.Context) {
	ticker := time.NewTicker(tuiFastWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.runFastProbe(ctx)
		}
	}
}

func (t *scanTUI) runFastProbe(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	t.mu.Lock()
	if t.rescanning {
		t.mu.Unlock()
		return
	}
	if !t.autoPing {
		t.mu.Unlock()
		return
	}
	watch := t.watch
	var suspects []string
	for ip, s := range t.pingStats {
		if s.misses >= 1 && s.misses < tuiDeadAfterMisses {
			suspects = append(suspects, ip)
		}
	}
	t.mu.Unlock()
	if len(suspects) == 0 {
		return
	}

	pings := pingSweep(ctx, suspects, watchPingTimeout(watch.timeout), tuiWatchPingConcurrency)

	t.mu.Lock()
	now := time.Now()
	changed := false
	for _, ip := range suspects {
		i := t.indexOfLocked(ip)
		if i < 0 {
			continue
		}
		before := t.hosts[i]
		if ms, ok := pings[ip]; ok {
			t.recordPingLocked(ip, ms)
			t.hosts[i].LatencyMS = ms
			if t.hosts[i].Status == "dead" {
				t.hosts[i].Status = ""
				if len(t.hosts[i].OpenPorts) > 0 {
					t.hosts[i].Status = "live"
				}
			}
			changed = true
		} else if n := t.recordMissLocked(ip); n >= tuiDeadAfterMisses && t.hosts[i].Status != "dead" {
			t.hosts[i].LatencyMS = -1
			t.hosts[i].Status = "dead"
			changed = true
		} else {
			changed = true // redraw so the fading-red ms cell advances
		}
		if hostStateChanged(before, t.hosts[i]) {
			t.hostChangedAt[ip] = now
		}
	}
	t.mu.Unlock()
	if changed {
		t.scheduleDraw()
	}
}

func (t *scanTUI) runPingTick(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	t.mu.Lock()
	if t.rescanning {
		t.mu.Unlock()
		return
	}
	watch := t.watch
	known := make(map[string]struct{}, len(t.hosts))
	for _, host := range t.hosts {
		known[host.IP] = struct{}{}
	}
	var batch []string
	if t.smallNet {
		batch = watch.ips
	} else if len(t.ipChunks) > 0 {
		batch = t.ipChunks[t.pingChunk]
		t.watchChunkNum = t.pingChunk + 1
		t.pingChunk = (t.pingChunk + 1) % len(t.ipChunks)
	}
	t.mu.Unlock()
	if len(batch) == 0 {
		return
	}

	_, ipNet, err := net.ParseCIDR(watch.enrich.targetCIDR)
	if err != nil {
		return
	}
	arpByIP := arpCacheForTarget(ipNet)

	pings := pingSweep(ctx, batch, watchPingTimeout(watch.timeout), tuiWatchPingConcurrency)

	batchSet := make(map[string]struct{}, len(batch))
	for _, ip := range batch {
		batchSet[ip] = struct{}{}
	}

	t.mu.Lock()
	now := time.Now()
	changed := false
	for i := range t.hosts {
		if entry, ok := arpByIP[t.hosts[i].IP]; ok {
			before := t.hosts[i]
			applyARPFromCache(&t.hosts[i], entry)
			if before.ARPType != t.hosts[i].ARPType ||
				before.ARPIfIndex != t.hosts[i].ARPIfIndex ||
				before.ARPIfAlias != t.hosts[i].ARPIfAlias ||
				before.MAC != t.hosts[i].MAC {
				changed = true
			}
			if t.hosts[i].MAC != "" && t.hosts[i].MACVendor == "" {
				t.hosts[i].MACVendor = macVendor(t.hosts[i].MAC)
				changed = true
			}
		}
	}
	for i := range t.hosts {
		ip := t.hosts[i].IP
		if _, inBatch := batchSet[ip]; !inBatch {
			continue
		}
		before := t.hosts[i]
		if ms, ok := pings[ip]; ok {
			t.recordPingLocked(ip, ms)
			t.hosts[i].LatencyMS = ms
			if t.hosts[i].Status == "dead" {
				t.hosts[i].Status = ""
				if len(t.hosts[i].OpenPorts) > 0 {
					t.hosts[i].Status = "live"
				}
			}
			changed = true
		} else if hostWasLive(t.hosts[i]) && t.missesLocked(ip) == 0 {
			// First miss only: flag the host suspect (red "-") and let the faster
			// fastLoop own escalation from here. Already-suspect hosts are skipped
			// so the 5s sweep can't double-count their misses.
			t.recordMissLocked(ip)
			changed = true
		}
		if t.watchPopulated && hostStateChanged(before, t.hosts[i]) {
			t.hostChangedAt[ip] = now
		}
	}
	t.watchPopulated = true
	t.mu.Unlock()

	for ip, ms := range pings {
		if _, ok := known[ip]; !ok {
			t.discoverHostAsync(ctx, watch, ip, ms, arpByIP)
		}
	}
	if watch.enrich.arpCache {
		for ip := range arpByIP {
			if _, ok := known[ip]; !ok {
				t.discoverHostAsync(ctx, watch, ip, -1, arpByIP)
			}
		}
	}
	if changed {
		t.scheduleDraw()
	}
}

func (t *scanTUI) discoverHostAsync(ctx context.Context, watch tuiWatchConfig, ip string, latencyMS int64, arpByIP map[string]arpCacheEntry) {
	if _, loaded := t.pendingDiscover.LoadOrStore(ip, struct{}{}); loaded {
		return
	}
	t.addDiscoverPlaceholder(ip, latencyMS)
	go func() {
		defer t.pendingDiscover.Delete(ip)
		t.discoverSem <- struct{}{}
		defer func() { <-t.discoverSem }()
		openPorts := scanIPPorts(ctx, ip, watch.ports, watch.timeout, watch.concurrency)
		if !shouldIncludeHost(openPorts, watch.enrich, arpByIP, ip) {
			t.removeHost(ip)
			return
		}
		liveIPs := map[string]struct{}{}
		if len(openPorts) > 0 {
			liveIPs[ip] = struct{}{}
		}
		arpDeadByIP := buildARPDeadByIP(arpByIP, liveIPs)
		host := enrichHost(ctx, ip, openPorts, watch.enrich, watch.timeout, arpByIP, arpDeadByIP, latencyMS)
		if watch.logger != nil {
			watch.logger.Printf("watch discovered ip=%s ports=%d latency_ms=%d guess=%s",
				host.IP, len(host.OpenPorts), host.LatencyMS, host.Guess)
		}
		t.upsertHost(host)
	}()
}

func (t *scanTUI) addDiscoverPlaceholder(ip string, latencyMS int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.indexOfLocked(ip) >= 0 {
		return
	}
	status := ""
	if latencyMS >= 0 {
		status = "live"
	}
	if t.phase == "watch" {
		t.hostDiscoveredAt[ip] = time.Now()
	}
	t.hosts = append(t.hosts, hostResult{IP: ip, LatencyMS: latencyMS, Status: status})
	sort.Slice(t.hosts, func(i, j int) bool { return lessIP(t.hosts[i].IP, t.hosts[j].IP) })
	if latencyMS >= 0 {
		t.recordPingLocked(ip, latencyMS)
	}
	t.scheduleDraw()
}

func (t *scanTUI) upsertHost(host hostResult) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.hosts {
		if t.hosts[i].IP == host.IP {
			if t.watchPopulated && hostStateChanged(t.hosts[i], host) {
				t.hostChangedAt[host.IP] = time.Now()
			}
			t.hosts[i] = host
			t.recordPingLocked(host.IP, host.LatencyMS)
			t.scheduleDraw()
			return
		}
	}
	if t.phase == "watch" {
		t.hostDiscoveredAt[host.IP] = time.Now()
	}
	t.recordPingLocked(host.IP, host.LatencyMS)
	t.hosts = append(t.hosts, host)
	sort.Slice(t.hosts, func(i, j int) bool { return lessIP(t.hosts[i].IP, t.hosts[j].IP) })
	t.scheduleDraw()
}

// tuiRowColor returns the full-row styling for a host. Dead hosts are colored
// red regardless of the ARP cache. A host whose state changed within the last
// tuiChangeHighlight window briefly gets reverse video as a non-color cue.
func tuiRowColor(host hostResult, now time.Time, changedAt map[string]time.Time) (prefix, suffix string) {
	var pre string
	if host.Status == "dead" {
		pre += escRed
	}
	if ts, ok := changedAt[host.IP]; ok && now.Sub(ts) < tuiChangeHighlight {
		pre += escReverse
	}
	if pre == "" {
		return "", ""
	}
	return pre, escReset
}

// tuiIsNewHost reports whether a host was discovered recently during watch.
func tuiIsNewHost(host hostResult, phase string, now time.Time, discoveredAt map[string]time.Time) bool {
	if phase != "watch" {
		return false
	}
	foundAt, ok := discoveredAt[host.IP]
	return ok && now.Sub(foundAt) < tuiNewHostHighlight
}

// tuiStatusGlyph encodes host state without relying on color. A suspect host
// (one or more recent misses, not yet dead) shows "!" to flag that it is being
// fast-probed.
func tuiStatusGlyph(host hostResult, phase string, now time.Time, discoveredAt map[string]time.Time, misses int) string {
	if tuiIsNewHost(host, phase, now, discoveredAt) {
		return "+"
	}
	if host.Status == "dead" {
		return "○"
	}
	if misses >= 1 {
		return "!"
	}
	if host.LatencyMS >= 0 || len(host.OpenPorts) > 0 {
		return "●"
	}
	return "·"
}

func tuiLatencyDisplay(ms int64) string {
	if ms < 0 {
		return "·"
	}
	return strconv.FormatInt(ms, 10)
}

func tuiLatencyColor(host hostResult) string {
	if host.Status == "dead" {
		return escRed
	}
	if host.LatencyMS < 0 {
		return escDim
	}
	switch {
	case host.LatencyMS <= 20:
		return escBrightGreen
	case host.LatencyMS <= 150:
		return escGreen
	case host.LatencyMS <= 400:
		return escYellow
	default:
		return escRed
	}
}

func statusGlyphColor(host hostResult, phase string, now time.Time, discoveredAt map[string]time.Time, misses int) string {
	if tuiIsNewHost(host, phase, now, discoveredAt) {
		return escBrightGreen
	}
	if host.Status == "dead" {
		return escRed
	}
	if misses >= 1 {
		return escYellow
	}
	if host.LatencyMS >= 0 || len(host.OpenPorts) > 0 {
		return escGreen
	}
	return escDim
}

func hostIPColor(host hostResult) string {
	if host.Status == "dead" {
		return escRed
	}
	if len(host.OpenPorts) > 0 || host.LatencyMS >= 0 {
		return escBrightCyan
	}
	return escCyan
}

func portsCellColor(host hostResult) string {
	if len(host.OpenPorts) > 0 {
		return escMagenta
	}
	return ""
}

// hostStateChanged reports a meaningful change worth highlighting: a status
// (up/down) transition or a change in the number of open ports. Latency is
// deliberately excluded because it jitters on nearly every ping, which would
// otherwise flash every live row on every watch tick.
func hostStateChanged(before, after hostResult) bool {
	return before.Status != after.Status ||
		len(before.OpenPorts) != len(after.OpenPorts)
}

// statsForLocked returns (creating if needed) the ping stats for an IP. The
// caller must hold t.mu.
func (t *scanTUI) statsForLocked(ip string) *hostPingStats {
	s := t.pingStats[ip]
	if s == nil {
		s = &hostPingStats{min: -1, max: -1}
		t.pingStats[ip] = s
	}
	return s
}

// recordPingLocked folds a successful latency sample into a host's stats and
// resets its miss counter. The caller must hold t.mu.
func (t *scanTUI) recordPingLocked(ip string, ms int64) {
	if ms < 0 {
		return
	}
	s := t.statsForLocked(ip)
	s.misses = 0
	s.samples = append(s.samples, ms)
	if len(s.samples) > tuiPingAvgWindow {
		s.samples = s.samples[len(s.samples)-tuiPingAvgWindow:]
	}
	if s.min < 0 || ms < s.min {
		s.min = ms
	}
	if ms > s.max {
		s.max = ms
	}
}

// recordMissLocked increments and returns a host's consecutive miss count. The
// caller must hold t.mu.
func (t *scanTUI) recordMissLocked(ip string) int {
	s := t.statsForLocked(ip)
	s.misses++
	return s.misses
}

func (t *scanTUI) missesLocked(ip string) int {
	if s := t.pingStats[ip]; s != nil {
		return s.misses
	}
	return 0
}

func (t *scanTUI) indexOfLocked(ip string) int {
	for i := range t.hosts {
		if t.hosts[i].IP == ip {
			return i
		}
	}
	return -1
}

// missColor returns a 256-color red escape that intensifies with the miss count
// so a struggling host's ms cell fades steadily redder. It honors NO_COLOR by
// returning "" whenever the base red has been blanked at startup.
func missColor(misses int) string {
	if escRed == "" || misses < 1 {
		return ""
	}
	span := tuiDeadAfterMisses - 1
	if span < 1 {
		span = 1
	}
	idx := (misses - 1) * (len(missRedRamp) - 1) / span
	if idx < 0 {
		idx = 0
	}
	if idx >= len(missRedRamp) {
		idx = len(missRedRamp) - 1
	}
	return fmt.Sprintf("\033[38;5;%dm", missRedRamp[idx])
}

// latencyCellText renders the current-latency cell: "down" once dead, a bare "-"
// while suspect (one or more recent misses), otherwise the latency value.
func latencyCellText(host hostResult, misses int) string {
	if host.Status == "dead" {
		return "down"
	}
	if misses >= 1 {
		return "-"
	}
	return tuiLatencyDisplay(host.LatencyMS)
}

// latencyCellColor colors the current-latency cell: red when dead, a fading red
// while suspect, otherwise the normal value tiers.
func latencyCellColor(host hostResult, misses int) string {
	if host.Status == "dead" {
		return escRed
	}
	if misses >= 1 {
		return missColor(misses)
	}
	return tuiLatencyColor(host)
}

// formatStatMS renders a min/max/avg latency value, capped for column width.
func formatStatMS(ms int64) string {
	if ms < 0 {
		return "·"
	}
	if ms > 9999 {
		ms = 9999
	}
	return strconv.FormatInt(ms, 10)
}

func spinnerFrame(n int64) string {
	if n < 0 {
		n = -n
	}
	return string(spinnerFrames[int(n)%len(spinnerFrames)])
}

// padRight left-aligns s in a field of width display columns, counting runes so
// multibyte glyphs (·, ○, ●, …) stay aligned where %-*s would over-count bytes.
func padRight(s string, width int) string {
	n := utf8.RuneCountInString(s)
	if n >= width {
		return s
	}
	return s + strings.Repeat(" ", width-n)
}

// wrapCell colors an already-padded cell, then restores rowPrefix so the inner
// reset does not cancel the surrounding row styling (red/reverse).
func wrapCell(padded, color, rowPrefix string) string {
	if color == "" {
		return padded
	}
	return color + padded + escReset + rowPrefix
}

func (t *scanTUI) removeHost(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.hosts {
		if t.hosts[i].IP == ip && t.hosts[i].MAC == "" && len(t.hosts[i].OpenPorts) == 0 {
			t.hosts = append(t.hosts[:i], t.hosts[i+1:]...)
			delete(t.hostDiscoveredAt, ip)
			delete(t.hostChangedAt, ip)
			delete(t.pingStats, ip)
			t.scheduleDraw()
			return
		}
	}
}

// WaitExit blocks until the user dismisses the finished TUI. While waiting it
// accepts single-key export commands (c/j/t) and q to quit. On Windows the
// console is switched to cbreak mode so keys register immediately; on unix it
// falls back to line-buffered input (press the letter then Enter).
func (t *scanTUI) WaitExit(ctx context.Context) {
	t.draw()
	if !isTerminal(os.Stdin) {
		fmt.Fprint(t.out, escShowCursor)
		return
	}
	restore, raw := enableRawMode(os.Stdin)
	defer restore()
	if !raw {
		fmt.Fprint(t.out, escShowCursor)
	}

	keys := make(chan tuiKey, 8)
	go func() {
		defer close(keys)
		reader := bufio.NewReader(os.Stdin)
		for {
			if raw {
				k, err := readKey(reader)
				if err != nil {
					return
				}
				keys <- k
				continue
			}
			line, err := reader.ReadString('\n')
			keys <- lineCommand(line)
			if err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case k, ok := <-keys:
			if !ok {
				return
			}
			switch k {
			case keyExit:
				return
			case keyCSV:
				t.doExport("csv")
			case keyJSON:
				t.doExport("json")
			case keyTXT:
				t.doExport("txt")
			case keyRescan:
				t.triggerRescan(ctx)
			case keyMacFormat:
				t.cycleMacFormat()
			case keyAutoPing:
				t.toggleAutoPing()
			case keyAutoScan:
				t.toggleAutoScan()
			case keyUp, keyDown, keyPageUp, keyPageDown, keyTop, keyBottom:
				t.scroll(k)
			}
		}
	}
}

// tuiKey is a decoded keypress/command from the results view.
type tuiKey int

const (
	keyNone tuiKey = iota
	keyExit
	keyCSV
	keyJSON
	keyTXT
	keyRescan
	keyMacFormat
	keyAutoPing
	keyAutoScan
	keyUp
	keyDown
	keyPageUp
	keyPageDown
	keyTop
	keyBottom
)

// readKey decodes a single keypress in raw mode, including the CSI escape
// sequences emitted by the arrow / Page / Home / End keys.
func readKey(r *bufio.Reader) (tuiKey, error) {
	b, err := r.ReadByte()
	if err != nil {
		return keyNone, err
	}
	switch b {
	case 'q', 'Q':
		return keyExit, nil
	case 'c', 'C':
		return keyCSV, nil
	case 'j', 'J':
		return keyJSON, nil
	case 't', 'T':
		return keyTXT, nil
	case 'r', 'R':
		return keyRescan, nil
	case 'm', 'M':
		return keyMacFormat, nil
	case 'p', 'P':
		return keyAutoPing, nil
	case 's', 'S':
		return keyAutoScan, nil
	case 'k':
		return keyUp, nil
	case 'g':
		return keyTop, nil
	case 'G':
		return keyBottom, nil
	case ' ', 'f':
		return keyPageDown, nil
	case 'b':
		return keyPageUp, nil
	case 0x1b:
		return parseEscape(r)
	}
	return keyNone, nil
}

// parseEscape decodes a CSI/SS3 sequence after the initial ESC. It reads the
// follow-up bytes with blocking reads rather than peeking at the buffer, because
// over a remote terminal (e.g. a web PowerShell console) the bytes of a single
// arrow-key sequence often arrive in separate reads — a buffered-only check
// would drop every arrow key. ESC is not itself a command here, so blocking for
// the rest of the sequence is harmless.
func parseEscape(r *bufio.Reader) (tuiKey, error) {
	b, err := r.ReadByte()
	if err != nil {
		return keyNone, err
	}
	if b != '[' && b != 'O' {
		return keyNone, nil
	}
	b, err = r.ReadByte()
	if err != nil {
		return keyNone, err
	}
	switch b {
	case 'A':
		return keyUp, nil
	case 'B':
		return keyDown, nil
	case 'H':
		return keyTop, nil
	case 'F':
		return keyBottom, nil
	}
	if b < '0' || b > '9' {
		return keyNone, nil // arrows we ignore (C/D) or other final bytes
	}
	// Numeric sequences end with '~' (possibly after a modifier like ";5").
	// Consume through the terminator so it can't leak into the next key.
	for {
		c, err := r.ReadByte()
		if err != nil {
			return keyNone, err
		}
		if c == '~' || (c >= 'A' && c <= 'Z') {
			break
		}
	}
	switch b {
	case '5':
		return keyPageUp, nil
	case '6':
		return keyPageDown, nil
	case '1', '7':
		return keyTop, nil
	case '4', '8':
		return keyBottom, nil
	}
	return keyNone, nil
}

// lineCommand maps a line of cooked-mode input (unix fallback) to a command.
func lineCommand(line string) tuiKey {
	s := strings.TrimSpace(line)
	if s == "" {
		return keyNone
	}
	switch s[0] {
	case 'q', 'Q':
		return keyExit
	case 'c', 'C':
		return keyCSV
	case 'j', 'J':
		return keyJSON
	case 't', 'T':
		return keyTXT
	case 'r', 'R':
		return keyRescan
	case 'm', 'M':
		return keyMacFormat
	case 'p', 'P':
		return keyAutoPing
	case 's', 'S':
		return keyAutoScan
	}
	return keyNone
}

// tuiMaxHostRows is the number of host rows that fit on screen, matching the
// reservation used by the draw routines for headers and footer.
func tuiMaxHostRows(rows int) int {
	if m := rows - 7; m > 1 {
		return m
	}
	return 1
}

// scroll adjusts the host viewport offset, clamped to the current host count
// and terminal height, then requests a redraw.
func (t *scanTUI) scroll(kind tuiKey) {
	_, rows := termColumnsRows(t.out)
	maxRows := tuiMaxHostRows(rows)
	t.mu.Lock()
	maxOff := len(t.hosts) - maxRows
	if maxOff < 0 {
		maxOff = 0
	}
	switch kind {
	case keyUp:
		t.scrollOff--
	case keyDown:
		t.scrollOff++
	case keyPageUp:
		t.scrollOff -= maxRows
	case keyPageDown:
		t.scrollOff += maxRows
	case keyTop:
		t.scrollOff = 0
	case keyBottom:
		t.scrollOff = maxOff
	}
	if t.scrollOff > maxOff {
		t.scrollOff = maxOff
	}
	if t.scrollOff < 0 {
		t.scrollOff = 0
	}
	t.mu.Unlock()
	t.scheduleDraw()
}

// triggerRescan runs a full port scan using the current watch config and replaces
// the host table when complete. Watch ping/discovery is paused until then.
func (t *scanTUI) triggerRescan(ctx context.Context) {
	t.mu.Lock()
	if t.rescanning || t.phase == "scanning" || t.phase == "enriching" {
		t.mu.Unlock()
		return
	}
	if t.phase != "watch" && t.phase != "done" {
		t.mu.Unlock()
		return
	}
	watch := t.watch
	total := int64(len(watch.ips) * len(watch.ports))
	t.rescanning = true
	t.phase = "scanning"
	t.hosts = nil
	t.scanHosts = map[string]int64{}
	t.hostTotal = 0
	t.scrollOff = 0
	t.pingStats = map[string]*hostPingStats{}
	t.hostDiscoveredAt = map[string]time.Time{}
	t.hostChangedAt = map[string]time.Time{}
	t.watchPopulated = false
	t.scanned.Store(0)
	t.total.Store(total)
	t.mu.Unlock()
	t.scheduleDraw()

	go func() {
		started := time.Now()
		hosts := scanNetwork(ctx, watch.ips, watch.ports, watch.timeout, watch.concurrency, watch.enrich, watch.logger, nil, t)
		t.applyRescanResults(hosts, time.Since(started), watch)
	}()
}

func (t *scanTUI) applyRescanResults(hosts []hostResult, elapsed time.Duration, watch tuiWatchConfig) {
	sort.Slice(hosts, func(i, j int) bool { return lessIP(hosts[i].IP, hosts[j].IP) })
	t.mu.Lock()
	t.rescanning = false
	t.phase = "watch"
	t.elapsed = elapsed
	t.hosts = append([]hostResult(nil), hosts...)
	t.hostTotal = len(hosts)
	for i := range t.hosts {
		if t.hosts[i].LatencyMS >= 0 {
			t.recordPingLocked(t.hosts[i].IP, t.hosts[i].LatencyMS)
		}
	}
	t.mu.Unlock()
	if watch.logger != nil {
		watch.logger.Printf("tui rescan completed hosts=%d duration=%s", len(hosts), elapsed)
	}
	t.scheduleDraw()
}

func cycleMacFormat(current string) string {
	switch current {
	case "dash":
		return "none"
	case "none":
		return "colon"
	default:
		return "dash"
	}
}

func macFormatStatusLabel(format string) string {
	switch format {
	case "dash":
		return "MAC format: dash (aa-bb-cc-dd-ee-ff)"
	case "none":
		return "MAC format: none (aabbccddeeff)"
	default:
		return "MAC format: colon (aa:bb:cc:dd:ee:ff)"
	}
}

func (t *scanTUI) cycleMacFormat() {
	t.mu.Lock()
	t.watch.macFormat = cycleMacFormat(t.watch.macFormat)
	t.exportStatus = macFormatStatusLabel(t.watch.macFormat)
	t.exportErr = false
	t.exportStatusAt = time.Now()
	t.mu.Unlock()
	t.scheduleDraw()
}

func (t *scanTUI) toggleAutoPing() {
	t.mu.Lock()
	t.autoPing = !t.autoPing
	on := t.autoPing
	t.exportStatus = "auto-ping " + onOffLabel(on)
	t.exportErr = false
	t.exportStatusAt = time.Now()
	t.mu.Unlock()
	t.scheduleDraw()
}

func (t *scanTUI) toggleAutoScan() {
	t.mu.Lock()
	t.autoScan = !t.autoScan
	on := t.autoScan
	t.exportStatus = "auto-scan " + onOffLabel(on)
	t.exportErr = false
	t.exportStatusAt = time.Now()
	t.mu.Unlock()
	t.scheduleDraw()
}

func onOffLabel(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

func toggleOnColor(on bool) string {
	if on {
		return escGreen
	}
	return escDim
}

// doExport writes the current results to a file and records a footer status.
func (t *scanTUI) doExport(format string) {
	path, err := t.exportResults(format)
	t.mu.Lock()
	if err != nil {
		t.exportStatus = "export failed: " + err.Error()
		t.exportErr = true
	} else {
		t.exportStatus = "exported -> " + path
		t.exportErr = false
	}
	t.exportStatusAt = time.Now()
	t.mu.Unlock()
	t.scheduleDraw()
}

// exportResults snapshots the hosts under the lock, releases it, then writes a
// timestamped file in the current working directory reusing the same serializers
// as the non-TUI -C/-j output (writeCSV/writeJSON) and printTable for txt.
func (t *scanTUI) exportResults(format string) (string, error) {
	t.mu.Lock()
	phase := t.phase
	macFormat := t.watch.macFormat
	report := scanReport{
		Scanner:     appName,
		Version:     appVersion,
		StartedAt:   t.watch.started,
		CompletedAt: t.watch.started.Add(t.elapsed),
		Target:      t.target,
		TimeoutMS:   t.watch.timeout.Milliseconds(),
		Concurrency: t.watch.concurrency,
		Ports:       t.watch.ports,
		Hosts:       append([]hostResult(nil), t.hosts...),
	}
	t.mu.Unlock()

	if phase != "watch" && phase != "done" {
		return "", fmt.Errorf("export only available once scanning completes")
	}
	if macFormat == "" {
		macFormat = "colon"
	}
	sort.Slice(report.Hosts, func(i, j int) bool { return lessIP(report.Hosts[i].IP, report.Hosts[j].IP) })

	name := "ipscry-export-" + time.Now().Format("20060102-150405") + "." + format
	abs, err := filepath.Abs(name)
	if err != nil {
		abs = name
	}
	switch format {
	case "csv":
		err = writeCSV(abs, report, macFormat)
	case "json":
		err = writeJSON(abs, report, macFormat)
	case "txt":
		err = writeTXT(abs, report, macFormat)
	default:
		return "", fmt.Errorf("unknown export format %q", format)
	}
	if err != nil {
		return "", err
	}
	return abs, nil
}

// writeTXT renders the plain-text console table (no ANSI codes) to a file.
func writeTXT(path string, report scanReport, macFormat string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	printTable(file, report, macFormat)
	return file.Close()
}

func (t *scanTUI) Close() {
	t.once.Do(func() {
		close(t.done)
		fmt.Fprint(t.out, escMainScreen, escShowCursor, escReset)
	})
}

func (t *scanTUI) draw() {
	t.mu.Lock()
	target := t.target
	total := t.total.Load()
	scanned := t.scanned.Load()
	phase := t.phase
	hostTotal := t.hostTotal
	elapsed := t.elapsed
	hosts := append([]hostResult(nil), t.hosts...)
	scrollOff := t.scrollOff
	hostsReady := 0
	for _, host := range hosts {
		if !hostRowPending(host) {
			hostsReady++
		}
	}
	macFormat := t.watch.macFormat
	if macFormat == "" {
		macFormat = "colon"
	}
	exportStatus := ""
	exportErr := false
	autoPing := t.autoPing
	autoScan := t.autoScan
	if t.exportStatus != "" && time.Since(t.exportStatusAt) < tuiExportStatusTTL {
		exportStatus = t.exportStatus
		exportErr = t.exportErr
	}
	discoveredAt := map[string]time.Time{}
	changedAt := map[string]time.Time{}
	pingView := map[string]hostPingView{}
	if phase == "watch" {
		for ip, foundAt := range t.hostDiscoveredAt {
			discoveredAt[ip] = foundAt
		}
		for ip, ts := range t.hostChangedAt {
			changedAt[ip] = ts
		}
		for ip, s := range t.pingStats {
			pingView[ip] = hostPingView{misses: s.misses, min: s.min, max: s.max, avg: s.avg()}
		}
	} else if phase == "scanning" || phase == "enriching" || phase == "done" {
		for ip, s := range t.pingStats {
			pingView[ip] = hostPingView{misses: s.misses, min: s.min, max: s.max, avg: s.avg()}
		}
	}
	t.mu.Unlock()

	frame := t.frame.Add(1)
	now := time.Now()
	cols, rows := termColumnsRows(t.out)
	var b strings.Builder

	spin := ""
	if phase == "scanning" || phase == "enriching" || phase == "watch" {
		spin = "  " + escCyan + spinnerFrame(frame) + escReset
	}
	fmt.Fprintf(&b, "%s%s%s%s %s%s  ·  %s%s%s  ·  %s\n\n",
		escBrightCyan, escBold, appName, escReset,
		escDim, appVersion,
		escYellow, target, escReset,
		phaseLabel(phase)+spin)

	if phase == "watch" {
		fmt.Fprintf(&b, "%d hosts · scan %s · watching\n\n", len(hosts), elapsed.Round(time.Millisecond))
	} else if phase == "done" {
		fmt.Fprintf(&b, "%d hosts  ·  %s\n\n", len(hosts), elapsed.Round(time.Millisecond))
	} else {
		fmt.Fprintf(&b, "%s\n\n", formatScanProgress(cols, scanned, total, len(hosts), phase, hostTotal, hostsReady))
	}

	switch phase {
	case "scanning", "enriching", "watch", "done":
		rowScroll := scrollOff
		if phase == "scanning" || phase == "enriching" {
			rowScroll = 0
		}
		showEnrichProgress := phase == "enriching"
		showARP := t.watch.enrich.tuiARPDetail
		t.drawHostRows(&b, hosts, hostTotal, cols, rows, showARP, phase, discoveredAt, changedAt, pingView, now, frame, rowScroll, macFormat, showEnrichProgress)
	}

	b.WriteString("\n")
	if phase == "watch" || phase == "done" {
		fmt.Fprintf(&b, "%sr rescan · %sp ping %s%s%s · %ss scan %s%s%s · m mac · q quit · c csv · j json · t txt%s\n",
			escDim,
			toggleOnColor(autoPing), onOffLabel(autoPing), escReset, escDim,
			toggleOnColor(autoScan), onOffLabel(autoScan), escReset, escDim, escReset)
		if exportStatus != "" {
			color := escGreen
			if exportErr {
				color = escRed
			}
			fmt.Fprintf(&b, "\n%s%s%s", color, exportStatus, escReset)
		}
	} else {
		fmt.Fprintf(&b, "%sCtrl+C to cancel%s", escDim, escReset)
	}

	frame2 := strings.ReplaceAll(b.String(), "\n", escClearLine+"\n")
	_, _ = io.WriteString(t.out, escHome+frame2+escClearDown)
}

type tuiColLayout struct {
	st, ip, name, mac, vendor, ports, ms, lavg, lmin, lmax, arpState, arpAlias, arpIndex int
}

func tuiDoneLayout(cols int, showARP bool) tuiColLayout {
	_ = cols
	arpState, arpAlias, arpIndex := 0, 0, 0
	if showARP {
		arpState, arpAlias, arpIndex = 11, 14, 5
	}
	return tuiColLayout{
		st:       1,
		ip:       15,
		name:     tuiNameWidth,
		mac:      17,
		vendor:   tuiVendorWidth,
		ports:    tuiPortsWidth,
		ms:       4,
		lavg:     3,
		lmin:     3,
		lmax:     3,
		arpState: arpState,
		arpAlias: arpAlias,
		arpIndex: arpIndex,
	}
}

func formatTuiVendorDisplay(vendor string) string {
	return truncDisplay(formatVendorDisplay(vendor), tuiVendorWidth)
}

func formatTuiNameDisplay(name string) string {
	return truncDisplay(orDash(name), tuiNameWidth)
}

func tuiDashCell(width int) string {
	return padRight("-", width)
}

func tuiMACCell(host hostResult, macFormat string, width int) string {
	if hostRowPending(host) || host.MAC == "" {
		return tuiDashCell(width)
	}
	return padRight(trunc(orDash(formatMAC(host.MAC, macFormat)), width), width)
}

func tuiPortsCell(host hostResult, width int) string {
	if hostRowPending(host) {
		return tuiDashCell(width)
	}
	return padRight(truncDisplay(formatPortsDisplay(host.OpenPorts), width), width)
}

func tuiVendorCell(host hostResult, width int) string {
	if hostRowPending(host) || host.MACVendor == "" {
		return tuiDashCell(width)
	}
	return padRight(formatTuiVendorDisplay(host.MACVendor), width)
}

func tuiNameCell(host hostResult, width int) string {
	if hostRowPending(host) || host.Hostname == "" {
		return tuiDashCell(width)
	}
	return padRight(formatTuiNameDisplay(host.Hostname), width)
}

func tuiARPCell(host hostResult, width int, value func(hostResult) string) string {
	if hostRowPending(host) && host.ARPType == "" && host.ARPIfIndex == 0 && host.ARPIfAlias == "" {
		return tuiDashCell(width)
	}
	return padRight(value(host), width)
}

func (t *scanTUI) drawHostRows(b *strings.Builder, hosts []hostResult, hostTotal, cols, rows int, showARP bool, phase string, discoveredAt, changedAt map[string]time.Time, pingView map[string]hostPingView, now time.Time, frame int64, scrollOff int, macFormat string, showProgress bool) {
	maxRows := tuiMaxHostRows(rows)
	total := len(hosts)
	off := 0
	allowScroll := phase == "watch" || phase == "done"
	if allowScroll && total > maxRows {
		off = scrollOff
		if maxOff := total - maxRows; off > maxOff {
			off = maxOff
		}
		if off < 0 {
			off = 0
		}
	}
	view := hosts
	if total > maxRows {
		view = hosts[off : off+maxRows]
	}

	lay := tuiDoneLayout(cols, showARP)
	b.WriteString(escBold + escBrightCyan)
	if showARP {
		fmt.Fprintf(b, "%-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s\n",
			lay.st, "S", lay.ip, "IP", lay.name, "Name", lay.mac, "MAC", lay.vendor, "Vendor", lay.ports, "Ports",
			lay.ms, "MS", lay.lavg, "AVG", lay.lmin, "MIN", lay.lmax, "MAX",
			lay.arpState, "State", lay.arpAlias, "Alias", lay.arpIndex, "Index")
	} else {
		fmt.Fprintf(b, "%-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s\n",
			lay.st, "S", lay.ip, "IP", lay.name, "Name", lay.mac, "MAC", lay.vendor, "Vendor", lay.ports, "Ports",
			lay.ms, "MS", lay.lavg, "AVG", lay.lmin, "MIN", lay.lmax, "MAX")
	}
	b.WriteString(escReset)
	for _, host := range view {
		pv := pingView[host.IP]
		prefix, reset := tuiRowColor(host, now, changedAt)
		stCell := wrapCell(padRight(tuiStatusGlyph(host, phase, now, discoveredAt, pv.misses), lay.st), statusGlyphColor(host, phase, now, discoveredAt, pv.misses), prefix)
		ipCell := wrapCell(padRight(host.IP, lay.ip), hostIPColor(host), prefix)
		msText := latencyCellText(host, pv.misses)
		if hostRowPending(host) && host.LatencyMS < 0 && pv.misses == 0 {
			msText = "-"
		}
		msCell := wrapCell(padRight(msText, lay.ms), latencyCellColor(host, pv.misses), prefix)
		macCell := tuiMACCell(host, macFormat, lay.mac)
		if !hostRowPending(host) && host.MAC != "" {
			macCell = wrapCell(macCell, escMagenta, prefix)
		}
		vendorCell := tuiVendorCell(host, lay.vendor)
		if host.MACVendor != "" {
			vendorCell = wrapCell(vendorCell, escBlue, prefix)
		} else if hostRowPending(host) {
			vendorCell = wrapCell(vendorCell, escDim, prefix)
		}
		nameCell := tuiNameCell(host, lay.name)
		if host.Hostname != "" {
			nameCell = wrapCell(nameCell, escBlue, prefix)
		} else if hostRowPending(host) {
			nameCell = wrapCell(nameCell, escDim, prefix)
		}
		var stateCell, aliasCell, indexCell string
		if showARP {
			stateCell = wrapCell(tuiARPCell(host, lay.arpState, formatARPState), escCyan, prefix)
			aliasCell = tuiARPCell(host, lay.arpAlias, func(h hostResult) string { return truncDisplay(formatARPAlias(h), lay.arpAlias) })
			indexCell = tuiARPCell(host, lay.arpIndex, formatARPIndex)
		}
		minCell := tuiDashCell(lay.lmin)
		maxCell := tuiDashCell(lay.lmax)
		avgCell := tuiDashCell(lay.lavg)
		if !hostRowPending(host) {
			minCell = padRight(formatStatMS(pv.min), lay.lmin)
			maxCell = padRight(formatStatMS(pv.max), lay.lmax)
			avgCell = padRight(formatStatMS(pv.avg), lay.lavg)
		}
		portsCell := wrapCell(tuiPortsCell(host, lay.ports), portsCellColor(host), prefix)
		if hostRowPending(host) {
			portsCell = wrapCell(portsCell, escDim, prefix)
		}
		b.WriteString(prefix)
		if showARP {
			fmt.Fprintf(b, "%s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",
				stCell, ipCell, nameCell, macCell, vendorCell, portsCell,
				msCell, avgCell, minCell, maxCell,
				stateCell, aliasCell, indexCell,
				reset,
			)
		} else {
			fmt.Fprintf(b, "%s %s %s %s %s %s %s %s %s %s %s\n",
				stCell, ipCell, nameCell, macCell, vendorCell, portsCell,
				msCell, avgCell, minCell, maxCell,
				reset,
			)
		}
	}
	if showProgress && hostTotal > 0 {
		ready := 0
		for _, host := range hosts {
			if !hostRowPending(host) {
				ready++
			}
		}
		if ready < hostTotal {
			fmt.Fprintf(b, "\n%sresolving %d/%d hosts… %s%s\n", escDim, ready, hostTotal, spinnerFrame(frame), escReset)
		}
	}
	if allowScroll && total > maxRows {
		fmt.Fprintf(b, "\n%sshowing %d-%d of %d  ·  %d above · %d below  ·  ↑/↓ or k, Space/b page, g/G ends%s\n",
			escDim, off+1, off+len(view), total, off, total-off-len(view), escReset)
	}
}

func phaseLabel(phase string) string {
	switch phase {
	case "scanning":
		return escBrightCyan + "scanning" + escReset
	case "enriching":
		return escYellow + "enriching" + escReset
	case "watch":
		return escBrightGreen + "watching" + escReset
	case "done":
		return escBrightGreen + "complete" + escReset
	default:
		return phase
	}
}

func progressPercent(done, total int64) int {
	if total <= 0 {
		return 0
	}
	pct := int(done * 100 / total)
	if pct > 100 {
		return 100
	}
	return pct
}

func portCountWidth(total int64) int {
	if total <= 0 {
		return 1
	}
	return len(strconv.FormatInt(total, 10))
}

func formatScanProgress(cols int, scanned, total int64, openHosts int, phase string, hostTotal, hostsReady int) string {
	const minBar, maxBar = 14, 52
	pct := progressPercent(scanned, total)
	countW := portCountWidth(total)

	var stats string
	if phase == "enriching" && hostTotal > 0 {
		hostW := portCountWidth(int64(hostTotal))
		stats = fmt.Sprintf(" %3d%%  %*d/%*d ports  ·  %*d/%*d hosts",
			pct, countW, scanned, countW, total, hostW, hostsReady, hostW, hostTotal)
	} else {
		stats = fmt.Sprintf(" %3d%%  %*d/%*d ports  ·  %d hosts",
			pct, countW, scanned, countW, total, openHosts)
	}

	prefix := "  "
	barWidth := cols - len(prefix) - len(stats) - 2 // brackets
	if barWidth < minBar {
		barWidth = minBar
	}
	if barWidth > maxBar {
		barWidth = maxBar
	}
	return prefix + progressBar(scanned, total, barWidth) + stats
}

func progressBar(done, total int64, width int) string {
	if width < 2 {
		width = 2
	}
	if total <= 0 {
		return escDim + "[" + strings.Repeat("─", width) + "]" + escReset
	}
	filled := int(done * int64(width) / total)
	if filled > width {
		filled = width
	}
	empty := width - filled
	var b strings.Builder
	b.WriteString(escDim)
	b.WriteByte('[')
	b.WriteString(escReset)
	if filled > 0 {
		b.WriteString(escBrightCyan)
		if filled >= width {
			b.WriteString(escBrightGreen)
		}
		b.WriteString(strings.Repeat("█", filled))
		b.WriteString(escReset)
	}
	if empty > 0 {
		b.WriteString(escDim)
		b.WriteString(strings.Repeat("░", empty))
	}
	b.WriteString(escDim)
	b.WriteByte(']')
	b.WriteString(escReset)
	return b.String()
}

func sortedKeys(m map[string]int) []string {
	return sortedIPs(m)
}

func sortedIPs[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return lessIP(keys[i], keys[j]) })
	return keys
}

func trunc(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// timeNewTicker isolates time.Ticker for tests; overridden in tui_test.go if needed.
var timeNewTicker = func(d time.Duration) *time.Ticker { return time.NewTicker(d) }
