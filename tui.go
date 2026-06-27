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
	tuiFastWatchInterval    = 1 * time.Second
	tuiWatchPingConcurrency = 128
	tuiWatchDiscoverWorkers = 4
	tuiNewHostHighlight     = 60 * time.Second
	tuiChangeHighlight      = 1500 * time.Millisecond
	tuiExportStatusTTL      = 4 * time.Second
	tuiDeadAfterMisses      = 10
	tuiPingAvgWindow        = 6
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
	Start(target string, totalPorts int64)
	PortProgress(scanned, total int64)
	PortOpen(ip string, latencyMS int64)
	EnrichStart(hostCount int)
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

func (t *scanTUI) Start(target string, totalPorts int64) {
	t.mu.Lock()
	t.target = target
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
	}
	t.mu.Unlock()
	t.scheduleDraw()
}

func (t *scanTUI) EnrichStart(hostCount int) {
	t.mu.Lock()
	t.phase = "enriching"
	t.hostTotal = hostCount
	t.mu.Unlock()
	t.scheduleDraw()
}

func (t *scanTUI) HostReady(host hostResult) {
	t.mu.Lock()
	t.hosts = append(t.hosts, host)
	t.mu.Unlock()
	t.scheduleDraw()
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
	for i := range t.hosts {
		if t.hosts[i].LatencyMS >= 0 {
			t.recordPingLocked(t.hosts[i].IP, t.hosts[i].LatencyMS)
		}
	}
	t.mu.Unlock()
	t.draw()
	go t.watchLoop(ctx)
	go t.fastLoop(ctx)
}

func (t *scanTUI) watchLoop(ctx context.Context) {
	t.runPingTick(ctx)
	ticker := time.NewTicker(tuiWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.runPingTick(ctx)
		}
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
		if entry, ok := arpByIP[ip]; ok {
			applyARPFromCache(&t.hosts[i], entry)
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
	if latencyMS >= 0 {
		t.upsertHost(hostResult{IP: ip, LatencyMS: latencyMS, Status: "live"})
	}
	go func() {
		defer t.pendingDiscover.Delete(ip)
		t.discoverSem <- struct{}{}
		defer func() { <-t.discoverSem }()
		openPorts := scanIPPorts(ctx, ip, watch.ports, watch.timeout, watch.concurrency)
		if !shouldIncludeHost(openPorts, watch.enrich, arpByIP, ip) {
			if latencyMS >= 0 {
				return
			}
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
		return ""
	}
	switch {
	case host.LatencyMS <= 20:
		return escGreen
	case host.LatencyMS <= 150:
		return escYellow
	default:
		return escRed
	}
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
	chunkNum := t.watchChunkNum
	chunkTotal := t.watchChunkTotal
	smallNet := t.smallNet
	scanHosts := make(map[string]int64, len(t.scanHosts))
	for ip, ms := range t.scanHosts {
		scanHosts[ip] = ms
	}
	hosts := append([]hostResult(nil), t.hosts...)
	scrollOff := t.scrollOff
	showARP := t.watch.enrich.arpCache
	exportStatus := ""
	exportErr := false
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
	}
	if phase == "watch" || phase == "done" {
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
	fmt.Fprintf(&b, "%s%s%s %s%s  ·  %s  ·  %s%s\n\n",
		escBold, appName, escReset, appVersion, escDim, target, phaseLabel(phase), spin)

	if phase == "watch" {
		fmt.Fprintf(&b, "%d hosts · scan %s · watching\n\n", len(hosts), elapsed.Round(time.Millisecond))
	} else if phase == "done" {
		fmt.Fprintf(&b, "%d hosts  ·  %s\n\n", len(hosts), elapsed.Round(time.Millisecond))
	} else {
		fmt.Fprintf(&b, "%s\n\n", formatScanProgress(cols, scanned, total, len(scanHosts), phase, hostTotal, len(hosts)))
	}

	switch phase {
	case "scanning":
		t.drawScanRows(&b, scanHosts, cols, rows)
	case "enriching":
		t.drawHostRows(&b, hosts, hostTotal, cols, rows, true, false, phase, discoveredAt, changedAt, pingView, now, frame, 0)
	case "watch", "done":
		t.drawHostRows(&b, hosts, 0, cols, rows, false, showARP, phase, discoveredAt, changedAt, pingView, now, frame, scrollOff)
	}

	b.WriteString("\n")
	if phase == "watch" || phase == "done" {
		ping := fmt.Sprintf("ping all every %ds", int(tuiWatchInterval.Seconds()))
		if !smallNet {
			ping = fmt.Sprintf("ping chunk %d/%d every %ds", chunkNum, chunkTotal, int(tuiWatchInterval.Seconds()))
		}
		fmt.Fprintf(&b, "%sq quit · c csv · j json · t txt · %s%s\n", escDim, ping, escReset)
		if exportStatus != "" {
			color := escGreen
			if exportErr {
				color = escRed
			}
			fmt.Fprintf(&b, "%s%s%s", color, exportStatus, escReset)
		} else {
			fmt.Fprintf(&b, "%s● up · ! missing · ○ down · + new · min/max/avg ms%s", escDim, escReset)
		}
	} else {
		fmt.Fprintf(&b, "%sCtrl+C to cancel%s", escDim, escReset)
	}

	frame2 := strings.ReplaceAll(b.String(), "\n", escClearLine+"\n")
	_, _ = io.WriteString(t.out, escHome+frame2+escClearDown)
}

func (t *scanTUI) drawScanRows(b *strings.Builder, scanHosts map[string]int64, cols, rows int) {
	lay := tuiScanLayout(cols)
	b.WriteString(escBold)
	fmt.Fprintf(b, "%-*s %-*s\n", lay.ip, "IP", lay.ms, "ms")
	b.WriteString(escReset)
	ips := sortedIPs(scanHosts)
	maxRows := rows - 7
	if maxRows < 1 {
		maxRows = 1
	}
	if len(ips) > maxRows {
		ips = ips[len(ips)-maxRows:]
	}
	for _, ip := range ips {
		fmt.Fprintf(b, "%-*s %-*s\n", lay.ip, ip, lay.ms, formatLatencyDisplay(scanHosts[ip]))
	}
}

type tuiColLayout struct {
	st, ip, mac, ms, lmin, lmax, lavg, typ, arpState, arpAlias, arpIndex, ports, name int
}

func tuiScanLayout(cols int) tuiColLayout {
	ip, ms := 15, 3
	if cols < ip+ms+2 {
		ip = cols - ms - 2
		if ip < 10 {
			ip = 10
		}
	}
	return tuiColLayout{ip: ip, ms: ms}
}

func tuiEnrichLayout(cols int) tuiColLayout {
	ip, mac, ms := 15, 17, 3
	name := cols - ip - mac - ms - 3
	if name < 16 {
		name = 16
	}
	return tuiColLayout{ip: ip, mac: mac, ms: ms, name: name}
}

func tuiDoneLayout(cols int, showARP bool) tuiColLayout {
	st, ip, mac, ms, typ := 1, 15, 17, 4, 10
	lmin, lmax, lavg := 4, 4, 4 // min/max/avg latency, capped at 9999ms
	arpState, arpAlias, arpIndex := 0, 0, 0
	gaps := 8 // st ip mac ms min max avg typ ports name -> 9 gaps; ports/name share rest
	if showARP {
		arpState, arpAlias, arpIndex = 11, 14, 5
		gaps = 11
	}
	overhead := st + ip + mac + ms + lmin + lmax + lavg + typ + arpState + arpAlias + arpIndex + gaps
	rest := cols - overhead
	if rest < 26 {
		rest = 26
	}
	ports := rest * 2 / 5
	if ports < 14 {
		ports = 14
	}
	if ports > 44 {
		ports = 44
	}
	name := rest - ports
	if name < 12 {
		name = 12
		if ports > rest-name {
			ports = rest - name
		}
	}
	return tuiColLayout{
		st: st, ip: ip, mac: mac, ms: ms, lmin: lmin, lmax: lmax, lavg: lavg, typ: typ,
		arpState: arpState, arpAlias: arpAlias, arpIndex: arpIndex,
		ports: ports, name: name,
	}
}

func (t *scanTUI) drawHostRows(b *strings.Builder, hosts []hostResult, hostTotal, cols, rows int, enriching, showARP bool, phase string, discoveredAt, changedAt map[string]time.Time, pingView map[string]hostPingView, now time.Time, frame int64, scrollOff int) {
	maxRows := tuiMaxHostRows(rows)
	total := len(hosts)
	off := 0
	if !enriching && total > maxRows {
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

	if enriching {
		lay := tuiEnrichLayout(cols)
		b.WriteString(escBold)
		fmt.Fprintf(b, "%-*s %-*s %-*s %s\n", lay.ip, "IP", lay.mac, "MAC", lay.ms, "ms", "Name")
		b.WriteString(escReset)
		for _, host := range view {
			fmt.Fprintf(b, "%-*s %-*s %-*s %s\n",
				lay.ip, host.IP,
				lay.mac, trunc(orDash(formatMAC(host.MAC, "colon")), lay.mac),
				lay.ms, tuiLatencyDisplay(host.LatencyMS),
				truncDisplay(orDash(host.Hostname), lay.name),
			)
		}
	} else {
		lay := tuiDoneLayout(cols, showARP)
		b.WriteString(escBold)
		if showARP {
			fmt.Fprintf(b, "%-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %s\n",
				lay.st, "S", lay.ip, "IP", lay.mac, "MAC", lay.ms, "ms",
				lay.lmin, "min", lay.lmax, "max", lay.lavg, "avg", lay.typ, "Type",
				lay.arpState, "State", lay.arpAlias, "Alias", lay.arpIndex, "Index",
				lay.ports, "Ports", "Name")
		} else {
			fmt.Fprintf(b, "%-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %s\n",
				lay.st, "S", lay.ip, "IP", lay.mac, "MAC", lay.ms, "ms",
				lay.lmin, "min", lay.lmax, "max", lay.lavg, "avg",
				lay.typ, "Type", lay.ports, "Ports", "Name")
		}
		b.WriteString(escReset)
		for _, host := range view {
			pv := pingView[host.IP]
			prefix, reset := tuiRowColor(host, now, changedAt)
			stCell := padRight(tuiStatusGlyph(host, phase, now, discoveredAt, pv.misses), lay.st)
			ipCell := padRight(host.IP, lay.ip)
			if tuiIsNewHost(host, phase, now, discoveredAt) {
				stCell = wrapCell(stCell, escGreen, prefix)
				ipCell = wrapCell(ipCell, escGreen, prefix)
			}
			msCell := wrapCell(padRight(latencyCellText(host, pv.misses), lay.ms), latencyCellColor(host, pv.misses), prefix)
			b.WriteString(prefix)
			if showARP {
				fmt.Fprintf(b, "%s %s %-*s %s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %s%s\n",
					stCell, ipCell,
					lay.mac, trunc(orDash(formatMAC(host.MAC, "colon")), lay.mac),
					msCell,
					lay.lmin, formatStatMS(pv.min),
					lay.lmax, formatStatMS(pv.max),
					lay.lavg, formatStatMS(pv.avg),
					lay.typ, formatGuessDisplay(host.Guess),
					lay.arpState, formatARPState(host),
					lay.arpAlias, truncDisplay(formatARPAlias(host), lay.arpAlias),
					lay.arpIndex, formatARPIndex(host),
					lay.ports, truncDisplay(formatPortsDisplay(host.OpenPorts), lay.ports),
					truncDisplay(orDash(host.Hostname), lay.name),
					reset,
				)
			} else {
				fmt.Fprintf(b, "%s %s %-*s %s %-*s %-*s %-*s %-*s %-*s %s%s\n",
					stCell, ipCell,
					lay.mac, trunc(orDash(formatMAC(host.MAC, "colon")), lay.mac),
					msCell,
					lay.lmin, formatStatMS(pv.min),
					lay.lmax, formatStatMS(pv.max),
					lay.lavg, formatStatMS(pv.avg),
					lay.typ, formatGuessDisplay(host.Guess),
					lay.ports, truncDisplay(formatPortsDisplay(host.OpenPorts), lay.ports),
					truncDisplay(orDash(host.Hostname), lay.name),
					reset,
				)
			}
		}
	}
	if enriching && hostTotal > len(hosts) {
		fmt.Fprintf(b, "\n%sresolving %d/%d hosts… %s%s\n", escDim, len(hosts), hostTotal, spinnerFrame(frame), escReset)
	}
	if !enriching && total > maxRows {
		fmt.Fprintf(b, "\n%sshowing %d-%d of %d  ·  %d above · %d below  ·  ↑/↓ or k, Space/b page, g/G ends%s\n",
			escDim, off+1, off+len(view), total, off, total-off-len(view), escReset)
	}
}

func phaseLabel(phase string) string {
	switch phase {
	case "scanning":
		return escCyan + "scanning" + escReset
	case "enriching":
		return escYellow + "enriching" + escReset
	case "watch":
		return escCyan + "watching" + escReset
	case "done":
		return escGreen + "complete" + escReset
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
		b.WriteString(escCyan)
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
