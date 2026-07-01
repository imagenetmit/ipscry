package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	appName     = "ipscry"
	maxFieldLen = 240 // max bytes retained for any sanitized free-text field

	// httpProbeTimeoutDefault is the default second-pass timeout for fully
	// retrieving HTTP/HTTPS page info from servers whose port was already
	// discovered with the shorter connect timeout. The discovery scan stays
	// fast; only confirmed web ports get this longer, deeper probe.
	httpProbeTimeoutDefault = 5 * time.Second
	// httpProbeConcurrency bounds the second-pass page retrievals. Page fetches
	// are heavier than connect dials, and the set of web ports is small, so this
	// is far lower than the port-scan concurrency.
	httpProbeConcurrency = 16
)

// appVersion is overridable at build time:
//
//	go build -ldflags "-X main.appVersion=1.2.3"
var appVersion = "0.1.0"

// portInfo is the single source of truth for a known port: its service label and
// which application-layer probes apply. Adding a port is a one-line edit here.
type portInfo struct {
	service string
	banner  bool // service announces a banner on connect (FTP, SSH, SMTP, ...)
	http    bool // speak HTTP(S) to collect status/server/title
	tls     bool // collect the TLS certificate subject
}

var portCatalog = map[int]portInfo{
	21:   {service: "ftp", banner: true},
	22:   {service: "ssh", banner: true},
	23:   {service: "telnet", banner: true},
	25:   {service: "smtp", banner: true},
	53:   {service: "dns"},
	80:   {service: "http", http: true},
	110:  {service: "pop3", banner: true},
	135:  {service: "msrpc"},
	139:  {service: "netbios"},
	143:  {service: "imap", banner: true},
	443:  {service: "https", http: true, tls: true},
	445:  {service: "smb"},
	515:  {service: "lpd"},
	554:  {service: "rtsp"},
	587:  {service: "smtp-submission"},
	631:  {service: "ipp", http: true},
	993:  {service: "imaps", tls: true},
	995:  {service: "pop3s", tls: true},
	1433: {service: "mssql"},
	1883: {service: "mqtt"},
	3306: {service: "mysql"},
	3389: {service: "rdp"},
	5432: {service: "postgres"},
	5900: {service: "vnc"},
	8000: {service: "http-alt", http: true},
	8008: {service: "http-alt", http: true},
	8080: {service: "http-alt", http: true},
	8443: {service: "https-alt", http: true, tls: true},
	8883: {service: "mqtts", tls: true},
	9100: {service: "jetdirect"},
	// Not in the default scan set; recognized when requested via --ports so the
	// service label and device guess are still meaningful.
	548:  {service: "afp"},
	902:  {service: "vmware"},
	2049: {service: "nfs"},
	5060: {service: "sip"},
	5061: {service: "sips", tls: true},
	5985: {service: "winrm"},
	5986: {service: "winrm-https", tls: true},
}

type scanConfig struct {
	Target        string
	Ports         []int
	Timeout       time.Duration
	Concurrency   int
	Progress      bool
	TUI           bool
	SNMPCommunity string
	JSONPath      string
	CSVPath       string
	LogPath       string
	WebhookURL    string
	MACFormat     string
	ARPCache      bool
	AIP           bool
	TUIARPDetail  bool
	HTTPTimeout   time.Duration
}

type scanReport struct {
	Scanner     string       `json:"scanner"`
	Version     string       `json:"version"`
	StartedAt   time.Time    `json:"started_at"`
	CompletedAt time.Time    `json:"completed_at"`
	Target      string       `json:"target"`
	TimeoutMS   int64        `json:"timeout_ms"`
	Concurrency int          `json:"concurrency"`
	Ports       []int        `json:"ports"`
	Hosts       []hostResult `json:"hosts"`
}

type hostResult struct {
	IP         string       `json:"ip"`
	MAC        string       `json:"mac,omitempty"`
	MACVendor  string       `json:"mac_vendor,omitempty"`
	LatencyMS  int64        `json:"latency_ms"`
	ARPType    string       `json:"arp_type,omitempty"`
	ARPIfIndex uint32       `json:"arp_ifindex,omitempty"`
	ARPIfAlias string       `json:"arp_ifalias,omitempty"`
	Hostname   string       `json:"hostname,omitempty"`
	SysName    string       `json:"snmp_sysname,omitempty"`
	SysDescr   string       `json:"snmp_sysdescr,omitempty"`
	OpenPorts  []portResult `json:"open_ports"`
	Guess      string       `json:"guess"`
	Status     string       `json:"status,omitempty"`
}

type portResult struct {
	Port         int    `json:"port"`
	Service      string `json:"service"`
	Vendors      string `json:"vendors,omitempty"`
	Banner       string `json:"banner,omitempty"`
	HTTPStatus   string `json:"http_status,omitempty"`
	HTTPServer   string `json:"http_server,omitempty"`
	HTTPTitle    string `json:"http_title,omitempty"`
	HTTPRedirect string `json:"http_redirect,omitempty"`
	TLSSubject   string `json:"tls_subject,omitempty"`
	ProbeError   string `json:"probe_error,omitempty"`
}

type portScanResult struct {
	ip        string
	port      portResult
	latencyMS int64
}

type arpCacheEntry struct {
	IP      string
	MAC     string
	Kind    string // dynamic, static
	IfIndex uint32
	IfAlias string
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer, stderr io.Writer) error {
	args, showHelp := stripHelpArgs(args)
	if showHelp {
		printUsage(stdout)
		return nil
	}
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version") {
		fmt.Fprintf(stdout, "%s %s\n", appName, appVersion)
		return nil
	}

	cfg, err := parseScanArgs(args)
	if err != nil {
		return err
	}
	if cfg.TUI {
		if err := checkTUINetworkSize(cfg.Target, os.Stdin, stderr); err != nil {
			return err
		}
	}

	logger, closeLog, err := configureLog(cfg.LogPath)
	if err != nil {
		return err
	}
	defer closeLog()

	started := time.Now().UTC()
	logger.Printf("scanner=%s version=%s started_at=%s target=%s ports=%s timeout=%s concurrency=%d",
		appName, appVersion, started.Format(time.RFC3339), cfg.Target, joinInts(cfg.Ports), cfg.Timeout, cfg.Concurrency)

	ips, err := expandCIDR(cfg.Target)
	if err != nil {
		return err
	}
	logger.Printf("expanded target=%s ip_count=%d", cfg.Target, len(ips))

	// Cancel in-flight dials on Ctrl-C; partial artifacts are still written below.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var progress io.Writer
	var monitor scanMonitor
	var tui *scanTUI
	if cfg.TUI {
		tui, err = newScanTUI(stdout)
		if err != nil {
			// No interactive terminal (piped/unattended); fall back to plain output.
			tui, cfg.TUI = nil, false
		} else {
			defer tui.Close()
			monitor = tui
		}
	}
	if !cfg.TUI && cfg.Progress {
		progress = stderr
	}
	enrich := enrichConfig{
		snmpCommunity: cfg.SNMPCommunity,
		arpCache:      cfg.ARPCache,
		targetCIDR:    cfg.Target,
		tuiARPDetail:  cfg.TUIARPDetail,
	}
	if tui != nil {
		tui.Start(cfg.Target, int64(len(ips)*len(cfg.Ports)), enrich)
	}
	hosts := scanNetwork(ctx, ips, cfg.Ports, cfg.Timeout, cfg.Concurrency, cfg.HTTPTimeout, enrich, logger, progress, monitor)
	completed := time.Now().UTC()
	elapsed := completed.Sub(started)
	if tui != nil {
		tui.Finish(hosts, elapsed, ctx, tuiWatchConfig{
			ips:         ips,
			ports:       cfg.Ports,
			timeout:     cfg.Timeout,
			concurrency: cfg.Concurrency,
			httpTimeout: cfg.HTTPTimeout,
			enrich:      enrich,
			logger:      logger,
			macFormat:   cfg.MACFormat,
			started:     started,
		})
	}

	for _, host := range hosts {
		logger.Printf("host ip=%s mac=%s latency_ms=%d status=%s arp_type=%s arp_ifindex=%d mac_vendor=%s hostname=%s guess=%s",
			host.IP, formatMAC(host.MAC, cfg.MACFormat), host.LatencyMS, host.Status, host.ARPType, host.ARPIfIndex, host.MACVendor, host.Hostname, host.Guess)
	}

	report := scanReport{
		Scanner:     appName,
		Version:     appVersion,
		StartedAt:   started,
		CompletedAt: completed,
		Target:      cfg.Target,
		TimeoutMS:   cfg.Timeout.Milliseconds(),
		Concurrency: cfg.Concurrency,
		Ports:       cfg.Ports,
		Hosts:       hosts,
	}

	if err := writeArtifacts(report, cfg); err != nil {
		return err
	}

	logger.Printf("completed_at=%s discovered_hosts=%d duration=%s", completed.Format(time.RFC3339), len(hosts), elapsed)
	if tui != nil {
		tui.WaitExit(ctx)
	} else if cfg.AIP {
		printAIPTable(stdout, report, cfg.MACFormat)
	} else {
		printTable(stdout, report, cfg.MACFormat)
	}
	return nil
}

func stripHelpArgs(args []string) ([]string, bool) {
	out := make([]string, 0, len(args))
	help := false
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			help = true
			continue
		}
		out = append(out, arg)
	}
	return out, help
}

func parseScanArgs(args []string) (scanConfig, error) {
	cfg := scanConfig{
		Ports:       append([]int(nil), defaultScanPorts...),
		Timeout:     250 * time.Millisecond,
		Concurrency: 1024,
	}

	fs := flag.NewFlagSet(appName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	ports := fs.String("ports", "common", "profile (common|web|windows|db), list, or ranges")
	timeout := fs.Duration("timeout", cfg.Timeout, "TCP connect timeout")
	concurrency := fs.Int("concurrency", cfg.Concurrency, "maximum concurrent port checks")
	noTUI := fs.Bool("no-tui", false, "disable the live terminal UI")
	snmpCommunity := fs.String("snmp-community", "public", "SNMP v2c community for enrichment (empty to disable)")
	jsonPath := fs.String("json", "", "write JSON results to path")
	csvPath := fs.String("csv", "", "write CSV results to path")
	logPath := fs.String("log", "", "write audit log to path")
	webhookURL := fs.String("webhook", "", "POST JSON results to URL")
	macFormat := fs.String("mac-format", "colon", "MAC format: colon, none, dash")
	arpCache := fs.Bool("arp-dead", false, "include IPs from the local ARP cache with no open ports")
	arpDetail := fs.Bool("arp-detail", false, "show ARP State/Alias/Index columns in the TUI")
	aipView := fs.Bool("aip", false, "display results like Advanced IP Scanner")
	httpTimeout := fs.Duration("http-timeout", httpProbeTimeoutDefault, "second-pass timeout for HTTP/HTTPS page retrieval")

	normalizedArgs, positional, err := normalizeScanArgs(args)
	if err != nil {
		return cfg, err
	}
	if err := fs.Parse(normalizedArgs); err != nil {
		return cfg, err
	}

	parsedPorts, err := parsePorts(*ports)
	if err != nil {
		return cfg, err
	}
	cfg.Ports = parsedPorts
	cfg.Timeout = *timeout
	cfg.Concurrency = *concurrency
	cfg.SNMPCommunity = *snmpCommunity
	cfg.JSONPath = strings.TrimSpace(*jsonPath)
	cfg.CSVPath = strings.TrimSpace(*csvPath)
	cfg.LogPath = strings.TrimSpace(*logPath)
	if raw := strings.TrimSpace(*webhookURL); raw != "" {
		parsed, err := parseWebhookURL(raw)
		if err != nil {
			return cfg, err
		}
		cfg.WebhookURL = parsed
	}
	cfg.MACFormat = strings.ToLower(strings.TrimSpace(*macFormat))
	cfg.ARPCache = *arpCache
	cfg.TUIARPDetail = *arpDetail
	cfg.AIP = *aipView
	cfg.HTTPTimeout = *httpTimeout
	if cfg.AIP {
		cfg.ARPCache = true
	}

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	hasOutputPath := set["json"] || set["csv"] || set["log"] || set["webhook"]

	cfg.TUI = !*noTUI && !hasOutputPath
	cfg.Progress = !cfg.TUI && !hasOutputPath

	if cfg.Timeout <= 0 {
		return cfg, errors.New("timeout must be greater than zero")
	}
	if cfg.HTTPTimeout <= 0 {
		return cfg, errors.New("http-timeout must be greater than zero")
	}
	if cfg.Concurrency < 1 || cfg.Concurrency > 2048 {
		return cfg, errors.New("concurrency must be between 1 and 2048")
	}
	switch cfg.MACFormat {
	case "colon", "none", "dash":
	default:
		return cfg, errors.New("mac-format must be colon, none, or dash")
	}

	switch {
	case len(positional) > 1:
		return cfg, errors.New("accept at most one target CIDR")
	case len(positional) == 1:
		cfg.Target = positional[0]
	default:
		// No target given: scan the active local /24.
		target, err := localCIDR()
		if err != nil {
			return cfg, err
		}
		cfg.Target = target
	}

	if _, _, err := net.ParseCIDR(cfg.Target); err != nil {
		return cfg, fmt.Errorf("invalid target CIDR %q: %w", cfg.Target, err)
	}
	return cfg, nil
}

// scanFlagAliases maps single-letter flags to their long names.
var scanFlagAliases = map[string]string{
	"p": "ports",
	"t": "timeout",
	"c": "concurrency",
	"N": "no-tui",
	"j": "json",
	"C": "csv",
	"L": "log",
	"w": "webhook",
	"m": "mac-format",
	"a": "arp-dead",
	"R": "arp-detail",
	"s": "snmp-community",
	"H": "http-timeout",
}

var scanValueFlags = map[string]bool{
	"ports": true, "timeout": true, "concurrency": true,
	"snmp-community": true, "json": true, "csv": true, "log": true, "webhook": true, "mac-format": true,
	"http-timeout": true,
}

func normalizeFlagToken(arg string) (string, error) {
	if !strings.HasPrefix(arg, "-") {
		return "", fmt.Errorf("not a flag: %s", arg)
	}
	body := strings.TrimLeft(arg, "-")
	suffix := ""
	if idx := strings.Index(body, "="); idx >= 0 {
		suffix = body[idx:]
		body = body[:idx]
	}
	if long, ok := scanFlagAliases[body]; ok {
		return "--" + long + suffix, nil
	}
	if scanValueFlags[body] || body == "no-tui" || body == "arp-dead" || body == "arp-detail" || body == "aip" {
		return "--" + body + suffix, nil
	}
	return "", fmt.Errorf("unknown flag %s", arg)
}

func normalizeScanArgs(args []string) ([]string, []string, error) {
	var flags []string
	var positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}
		normalized, err := normalizeFlagToken(arg)
		if err != nil {
			return nil, nil, err
		}
		flags = append(flags, normalized)
		name := normalized
		if idx := strings.Index(normalized, "="); idx >= 0 {
			name = normalized[:idx]
		}
		longName := strings.TrimPrefix(name, "--")
		if scanValueFlags[longName] && !strings.Contains(normalized, "=") {
			if i+1 >= len(args) {
				return nil, nil, fmt.Errorf("missing value for %s", arg)
			}
			i++
			flags = append(flags, args[i])
		}
	}
	return flags, positional, nil
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `%s %s

Usage:
  ipscry [CIDR] [options]
  ipscry version

With no CIDR, scans the active local /24.

Options:
  -h, --help
  -p, --ports common|web|windows|db | 22,80,443 | 8000-8100
  -t, --timeout 250ms
  -c, --concurrency 1024
  -N, --no-tui          disable the live terminal UI
  -s, --snmp-community public
  -j, --json PATH       write JSON results (optional)
  -C, --csv PATH        write CSV results (optional)
  -L, --log PATH        write audit log (optional)
  -w, --webhook URL     POST JSON results to HTTP endpoint (optional)
  -m, --mac-format colon|none|dash
  -a, --arp-dead        include offline hosts from the local ARP cache
  -R, --arp-detail      show ARP State/Alias/Index columns in the TUI
      --aip             Advanced IP Scanner-style results table
  -H, --http-timeout 5s second-pass timeout for HTTP/HTTPS page retrieval
`, appName, appVersion)
}

// portProfiles are named port sets selectable via --ports <name>.
// "common" is not listed here; it always mirrors embedded data/ports.csv.
var portProfiles = map[string][]int{
	"web":     {80, 443, 631, 8000, 8008, 8080, 8443},
	"windows": {135, 139, 445, 1433, 3389, 5985, 5986},
	"db":      {1433, 3306, 5432},
}

func parsePorts(input string) ([]int, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return append([]int(nil), defaultScanPorts...), nil
	}
	lower := strings.ToLower(input)
	if lower == "common" {
		return append([]int(nil), defaultScanPorts...), nil
	}
	if profile, ok := portProfiles[lower]; ok {
		out := append([]int(nil), profile...)
		sort.Ints(out)
		return out, nil
	}

	seen := map[int]bool{}
	var ports []int
	add := func(port int) {
		if !seen[port] {
			seen[port] = true
			ports = append(ports, port)
		}
	}
	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			start, err1 := strconv.Atoi(strings.TrimSpace(lo))
			end, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			for port := start; port <= end; port++ {
				add(port)
			}
			continue
		}
		port, err := strconv.Atoi(part)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		add(port)
	}
	if len(ports) == 0 {
		return nil, errors.New("at least one port is required")
	}
	sort.Ints(ports)
	return ports, nil
}

func configureLog(path string) (*log.Logger, func(), error) {
	if path == "" {
		return log.New(io.Discard, "", 0), func() {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, func() {}, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, func() {}, err
	}
	return log.New(file, "", log.LstdFlags|log.LUTC), func() { _ = file.Close() }, nil
}

func localCIDR() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, ok := ipv4FromAddr(addr)
			if !ok || !isPrivateIPv4(ip) {
				continue
			}
			ip = ip.To4()
			return fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2]), nil
		}
	}
	return "", errors.New("no active private IPv4 adapter found; provide an explicit CIDR")
}

func ipv4FromAddr(addr net.Addr) (net.IP, bool) {
	switch v := addr.(type) {
	case *net.IPNet:
		ip := v.IP.To4()
		return ip, ip != nil
	case *net.IPAddr:
		ip := v.IP.To4()
		return ip, ip != nil
	default:
		return nil, false
	}
}

func isPrivateIPv4(ip net.IP) bool {
	ip = ip.To4()
	if ip == nil {
		return false
	}
	return ip[0] == 10 ||
		(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
		(ip[0] == 192 && ip[1] == 168)
}

const (
	tuiMaxPrefix  = 22 // largest network allowed in TUI (/22 ≈ 1022 hosts)
	tuiWarnPrefix = 23 // warn and confirm for /23 and /22
)

func cidrPrefixLen(cidr string) (int, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, err
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		return 0, errors.New("only IPv4 CIDRs are supported")
	}
	return ones, nil
}

func cidrUsableHostCount(prefix int) int {
	if prefix < 0 || prefix > 32 {
		return 0
	}
	addrs := 1 << (32 - prefix)
	if addrs <= 2 {
		return 0
	}
	return addrs - 2
}

// checkTUINetworkSize rejects TUI scans larger than /22 and prompts before /22
// or /23 scans because large result sets overwhelm the terminal UI.
func checkTUINetworkSize(target string, stdin io.Reader, stderr io.Writer) error {
	prefix, err := cidrPrefixLen(target)
	if err != nil {
		return fmt.Errorf("invalid target CIDR %q: %w", target, err)
	}
	if prefix > tuiWarnPrefix {
		return nil
	}
	if prefix < tuiMaxPrefix {
		return fmt.Errorf(
			"TUI mode cannot scan networks larger than /22 (~%d hosts). "+
				"Split the target into smaller chunks such as /24, /23, or /22, or run with --no-tui",
			cidrUsableHostCount(tuiMaxPrefix),
		)
	}

	hosts := cidrUsableHostCount(prefix)
	fmt.Fprintf(stderr,
		"Warning: scanning %s (~%d hosts) in TUI mode may overwhelm the terminal display.\n"+
			"Consider splitting into /24 chunks, or use --no-tui for large scans.\n"+
			"Continue? [y/N]: ",
		target, hosts,
	)
	if f, ok := stdin.(*os.File); ok && !isTerminal(f) {
		return errors.New("cannot confirm large TUI scan without an interactive terminal; use a smaller CIDR or --no-tui")
	}
	ok, err := confirmPrompt(stdin)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("scan cancelled")
	}
	return nil
}

func confirmPrompt(r io.Reader) (bool, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

func expandCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ip = ip.To4()
	if ip == nil {
		return nil, errors.New("only IPv4 CIDRs are supported")
	}

	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones < 16 {
		return nil, errors.New("refusing to scan CIDRs larger than /16")
	}

	var ips []string
	for current := ip.Mask(ipNet.Mask); ipNet.Contains(current); incIP(current) {
		cp := append(net.IP(nil), current...)
		ips = append(ips, cp.String())
	}
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

func arpCacheForTarget(ipNet *net.IPNet) map[string]arpCacheEntry {
	out := map[string]arpCacheEntry{}
	for _, entry := range arpCacheEntries() {
		if !ipInTarget(entry.IP, ipNet) || !validARPMAC(entry.MAC) {
			continue
		}
		out[entry.IP] = entry
	}
	return out
}

func arpCacheEntryForIP(ip, targetCIDR string) (arpCacheEntry, bool) {
	_, ipNet, err := net.ParseCIDR(targetCIDR)
	if err != nil || !ipInTarget(ip, ipNet) {
		return arpCacheEntry{}, false
	}
	for _, entry := range arpCacheEntries() {
		if entry.IP == ip && validARPMAC(entry.MAC) {
			return entry, true
		}
	}
	return arpCacheEntry{}, false
}

func mergeARPCacheHosts(live map[string]struct{}, entries []arpCacheEntry, ipNet *net.IPNet) []arpCacheEntry {
	var out []arpCacheEntry
	for _, entry := range entries {
		if _, ok := live[entry.IP]; ok {
			continue
		}
		if !ipInTarget(entry.IP, ipNet) || !validARPMAC(entry.MAC) {
			continue
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return lessIP(out[i].IP, out[j].IP) })
	return out
}

func ipInTarget(ip string, ipNet *net.IPNet) bool {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil || !ipNet.Contains(parsed) {
		return false
	}
	if parsed.Equal(ipNet.IP.To4()) {
		return false
	}
	broadcast := make(net.IP, len(parsed))
	for i := range parsed {
		broadcast[i] = ipNet.IP[i] | ^ipNet.Mask[i]
	}
	return !parsed.Equal(broadcast.To4())
}

func validARPMAC(mac string) bool {
	hex := macHexDigits(mac)
	if len(hex) != 12 || hex == "000000000000" || hex == "FFFFFFFFFFFF" {
		return false
	}
	first, err := strconv.ParseUint(hex[0:2], 16, 8)
	if err != nil || first&1 == 1 {
		return false
	}
	return true
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// enrichConfig carries the optional per-host enrichment steps applied after a
// host's open ports are known.
type enrichConfig struct {
	snmpCommunity string
	arpCache      bool
	targetCIDR    string
	tuiARPDetail  bool
}

func scanNetwork(ctx context.Context, ips []string, ports []int, timeout time.Duration, concurrency int, httpTimeout time.Duration, enrich enrichConfig, logger *log.Logger, progress io.Writer, monitor scanMonitor) []hostResult {
	if ctx == nil {
		ctx = context.Background()
	}
	type job struct {
		ip   string
		port int
	}
	jobs := make(chan job, concurrency*2)
	results := make(chan portScanResult, concurrency)

	total := int64(len(ips) * len(ports))
	var scanned int64

	var workers sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := range jobs {
				if result, ok := scanPort(ctx, j.ip, j.port, timeout); ok {
					results <- result
				}
				atomic.AddInt64(&scanned, 1)
			}
		}()
	}

	go func() {
		for _, ip := range ips {
			for _, port := range ports {
				jobs <- job{ip: ip, port: port}
			}
		}
		close(jobs)
		workers.Wait()
		close(results)
	}()

	// Optional periodic progress while results stream in.
	stopProgress := make(chan struct{})
	if total > 0 && (progress != nil || monitor != nil) {
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stopProgress:
					return
				case <-ticker.C:
					n := atomic.LoadInt64(&scanned)
					if monitor != nil {
						monitor.PortProgress(n, total)
					}
					if progress != nil {
						fmt.Fprintf(progress, "\rscanning %d/%d ports...", n, total)
					}
				}
			}
		}()
	}

	byIP := map[string][]portResult{}
	for result := range results {
		byIP[result.ip] = append(byIP[result.ip], result.port)
		if monitor != nil {
			monitor.PortOpen(result.ip, result.latencyMS)
		}
		logger.Printf("open ip=%s port=%d service=%s", result.ip, result.port.Port, result.port.Service)
	}
	close(stopProgress)
	if progress != nil && total > 0 {
		fmt.Fprintf(progress, "\rscanned %d/%d ports        \n", atomic.LoadInt64(&scanned), total)
	}
	if monitor != nil && total > 0 {
		monitor.PortProgress(total, total)
	}

	_, ipNet, err := net.ParseCIDR(enrich.targetCIDR)
	if err != nil {
		return nil
	}
	arpByIP := arpCacheForTarget(ipNet)
	arpDeadByIP := map[string]arpCacheEntry{}
	if enrich.arpCache {
		liveIPs := make(map[string]struct{}, len(byIP))
		for ip := range byIP {
			liveIPs[ip] = struct{}{}
		}
		for ip, entry := range arpByIP {
			if _, live := liveIPs[ip]; live {
				continue
			}
			arpDeadByIP[ip] = entry
			if _, ok := byIP[ip]; !ok {
				byIP[ip] = nil
			}
		}
	}

	var hosts []hostResult
	var hostMu sync.Mutex
	var hostWorkers sync.WaitGroup
	enrichIPs := make([]string, 0, len(byIP))
	for ip := range byIP {
		enrichIPs = append(enrichIPs, ip)
	}
	sort.Slice(enrichIPs, func(i, j int) bool { return lessIP(enrichIPs[i], enrichIPs[j]) })
	if monitor != nil {
		monitor.EnrichStart(enrichIPs, enrich)
	}
	for ip, openPorts := range byIP {
		ip := ip
		openPorts := openPorts
		sort.Slice(openPorts, func(i, j int) bool { return openPorts[i].Port < openPorts[j].Port })
		hostWorkers.Add(1)
		go func() {
			defer hostWorkers.Done()
			host := enrichHost(ctx, ip, openPorts, enrich, timeout, arpByIP, arpDeadByIP, -1)
			hostMu.Lock()
			hosts = append(hosts, host)
			hostMu.Unlock()
			if monitor != nil {
				monitor.HostReady(host)
			}
		}()
	}
	hostWorkers.Wait()
	sort.Slice(hosts, func(i, j int) bool {
		return lessIP(hosts[i].IP, hosts[j].IP)
	})
	// Second pass: fully retrieve HTTP/HTTPS page info from web ports that the
	// short connect timeout left unprobed. Synchronous when there is no TUI so
	// console/JSON/CSV/webhook output carries the richer metadata; background
	// when a TUI monitor is attached so host rows fill in live without delaying
	// the watch phase.
	runDeepHTTPProbe(ctx, hosts, httpTimeout, httpProbeConcurrency, monitor, logger)
	return hosts
}

func scanIPPorts(ctx context.Context, ip string, ports []int, timeout time.Duration, concurrency int) []portResult {
	if concurrency < 1 {
		concurrency = 1
	}
	var mu sync.Mutex
	var open []portResult
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, port := range ports {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			if result, ok := scanPort(ctx, ip, port, timeout); ok {
				mu.Lock()
				open = append(open, result.port)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return open
}

func enrichHost(ctx context.Context, ip string, openPorts []portResult, enrich enrichConfig, timeout time.Duration, arpByIP map[string]arpCacheEntry, arpDeadByIP map[string]arpCacheEntry, latencyMS int64) hostResult {
	hostname := resolveHostname(ctx, ip, openPorts, timeout)
	var sysName, sysDescr string
	if enrich.snmpCommunity != "" {
		sysName, sysDescr = snmpGet(ctx, ip, enrich.snmpCommunity, minDuration(timeout, time.Second))
	}
	if hostname == "" {
		hostname = sysName
	}
	arpEntry, inARP := arpByIP[ip]
	mac := ""
	arpType := ""
	var arpIfIndex uint32
	arpIfAlias := ""
	if inARP {
		mac = arpEntry.MAC
		arpType = arpEntry.Kind
		arpIfIndex = arpEntry.IfIndex
		arpIfAlias = arpEntry.IfAlias
	}
	if mac == "" {
		mac = lookupMAC(ip)
	}
	vendor := ""
	if mac != "" {
		vendor = macVendor(mac)
	}
	latency := latencyMS
	if latency < 0 {
		if ms, ok := pingHost(ctx, ip, minDuration(timeout, 2*time.Second)); ok {
			latency = ms
		}
	}
	status := ""
	guess := guessDevice(openPorts, sysDescr)
	if enrich.arpCache {
		if len(openPorts) > 0 {
			status = "live"
		} else if _, ok := arpDeadByIP[ip]; ok {
			status = "arp"
			guess = "offline"
		}
	}
	host := hostResult{
		IP:         ip,
		MAC:        mac,
		MACVendor:  vendor,
		LatencyMS:  latency,
		ARPType:    arpType,
		ARPIfIndex: arpIfIndex,
		ARPIfAlias: arpIfAlias,
		Hostname:   hostname,
		SysName:    sysName,
		SysDescr:   sysDescr,
		OpenPorts:  openPorts,
		Guess:      guess,
		Status:     status,
	}
	fillARPFromCache(&host, enrich.targetCIDR)
	return host
}

func shouldIncludeHost(openPorts []portResult, enrich enrichConfig, arpByIP map[string]arpCacheEntry, ip string) bool {
	if len(openPorts) > 0 {
		return true
	}
	if enrich.arpCache {
		if _, ok := arpByIP[ip]; ok {
			return true
		}
	}
	return false
}

func buildARPDeadByIP(arpByIP map[string]arpCacheEntry, liveIPs map[string]struct{}) map[string]arpCacheEntry {
	arpDeadByIP := map[string]arpCacheEntry{}
	for ip, entry := range arpByIP {
		if _, live := liveIPs[ip]; live {
			continue
		}
		arpDeadByIP[ip] = entry
	}
	return arpDeadByIP
}

func pingSweep(ctx context.Context, ips []string, timeout time.Duration, concurrency int) map[string]int64 {
	if concurrency < 1 {
		concurrency = 1
	}
	pingTimeout := minDuration(timeout, 2*time.Second)
	results := make(map[string]int64, len(ips))
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			ms, ok := pingHost(ctx, ip, pingTimeout)
			if !ok {
				return
			}
			mu.Lock()
			results[ip] = ms
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return results
}

const tuiWatchChunkSize = 256

func splitIPChunks(ips []string, size int) [][]string {
	if size <= 0 || len(ips) <= size {
		return [][]string{ips}
	}
	chunks := make([][]string, 0, (len(ips)+size-1)/size)
	for i := 0; i < len(ips); i += size {
		end := i + size
		if end > len(ips) {
			end = len(ips)
		}
		chunks = append(chunks, ips[i:end])
	}
	return chunks
}

func watchPingTimeout(timeout time.Duration) time.Duration {
	return minDuration(timeout, 500*time.Millisecond)
}

func scanPort(ctx context.Context, ip string, port int, timeout time.Duration) (portScanResult, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	info := portCatalog[port]
	pr := portResult{Port: port, Service: serviceLabel(port), Vendors: portVendors(port)}

	// HTTP ports: the HTTP client performs its own dial. A response (any status)
	// proves the port is open and yields the richest metadata in one round-trip.
	if info.http {
		start := time.Now()
		if probeHTTP(ctx, ip, port, timeout, &pr) {
			return portScanResult{ip: ip, port: pr, latencyMS: time.Since(start).Milliseconds()}, true
		}
		// Probe failed; pr.ProbeError is retained and we fall through to a plain
		// TCP check so an open-but-not-HTTP port is still reported.
	}

	// TLS-only ports: dial with TLS directly so the single connection both proves
	// the port is open and surfaces the certificate subject.
	if info.tls && !info.http {
		start := time.Now()
		if probeTLS(ctx, ip, port, timeout, &pr) {
			return portScanResult{ip: ip, port: pr, latencyMS: time.Since(start).Milliseconds()}, true
		}
	}

	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return portScanResult{}, false
	}
	defer conn.Close()
	latencyMS := time.Since(start).Milliseconds()

	if info.banner {
		_ = conn.SetReadDeadline(time.Now().Add(minDuration(timeout, 300*time.Millisecond)))
		buf := make([]byte, 256)
		if n, err := conn.Read(buf); err == nil && n > 0 {
			pr.Banner = sanitizeOneLine(string(buf[:n]))
		}
	}

	return portScanResult{ip: ip, port: pr, latencyMS: latencyMS}, true
}

func probeHTTP(ctx context.Context, ip string, port int, timeout time.Duration, pr *portResult) bool {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(ip, strconv.Itoa(port)))
	client := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // inventory only; do not trust remote identity.
			Proxy:           nil,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		pr.ProbeError = err.Error()
		return false
	}
	req.Header.Set("User-Agent", "ipscry/"+appVersion)
	resp, err := client.Do(req)
	if err != nil {
		pr.ProbeError = sanitizeOneLine(err.Error())
		return false
	}
	defer resp.Body.Close()
	pr.HTTPStatus = resp.Status
	if code := resp.StatusCode; code >= 300 && code < 400 {
		if loc := strings.TrimSpace(resp.Header.Get("Location")); loc != "" {
			if base := resp.Request.URL; base != nil {
				if abs, err := base.Parse(loc); err == nil {
					loc = abs.String()
				}
			}
			pr.HTTPRedirect = sanitizeOneLine(loc)
		}
	}
	pr.HTTPServer = sanitizeOneLine(resp.Header.Get("Server"))
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		pr.TLSSubject = sanitizeOneLine(resp.TLS.PeerCertificates[0].Subject.String())
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	pr.HTTPTitle = extractTitle(string(body))
	return true
}

// portNeedsHTTPProbe reports whether an open web port still lacks an HTTP
// response, meaning the short connect-timeout probe timed out before any page
// info could be collected. These ports get a longer second pass.
func portNeedsHTTPProbe(pr portResult) bool {
	info, ok := portCatalog[pr.Port]
	return ok && info.http && pr.HTTPStatus == ""
}

// deepProbeHTTPPort re-runs the HTTP(S) page retrieval against an already-open
// web port using the longer second-pass timeout. Only the per-port HTTP/TLS
// metadata fields are populated; discovery-only fields (Port/Service/Vendors)
// are preserved from the original result.
func deepProbeHTTPPort(ctx context.Context, ip string, pr portResult, timeout time.Duration) portResult {
	out := portResult{
		Port:    pr.Port,
		Service: pr.Service,
		Vendors: pr.Vendors,
		Banner:  pr.Banner,
	}
	probeHTTP(ctx, ip, pr.Port, timeout, &out)
	return out
}

// runDeepHTTPProbe schedules second-pass HTTP/HTTPS page retrievals for every
// open web port the discovery scan could not fully probe. With a monitor
// attached (TUI) it runs in the background and streams refreshed ports back via
// HTTPRefresh; without one it runs synchronously and mutates hosts in place so
// non-TUI output reflects the fuller metadata.
func runDeepHTTPProbe(ctx context.Context, hosts []hostResult, timeout time.Duration, concurrency int, monitor scanMonitor, logger *log.Logger) {
	if timeout <= 0 || ctx.Err() != nil {
		return
	}
	type httpJob struct {
		hostIdx int
		portIdx int
		ip      string
		port    portResult
	}
	var jobs []httpJob
	for i := range hosts {
		for j := range hosts[i].OpenPorts {
			if portNeedsHTTPProbe(hosts[i].OpenPorts[j]) {
				jobs = append(jobs, httpJob{i, j, hosts[i].IP, hosts[i].OpenPorts[j]})
			}
		}
	}
	if len(jobs) == 0 {
		return
	}
	if logger != nil {
		logger.Printf("http deep probe start targets=%d timeout=%s concurrency=%d", len(jobs), timeout, concurrency)
	}

	work := func() {
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup
		for _, j := range jobs {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(j httpJob) {
				defer wg.Done()
				defer func() { <-sem }()
				updated := deepProbeHTTPPort(ctx, j.ip, j.port, timeout)
				if updated.HTTPStatus == "" {
					return // second attempt also failed; leave the original port untouched
				}
				if monitor != nil {
					monitor.HTTPRefresh(hostResult{IP: j.ip, OpenPorts: []portResult{updated}})
					return
				}
				if j.hostIdx < len(hosts) && hosts[j.hostIdx].IP == j.ip &&
					j.portIdx < len(hosts[j.hostIdx].OpenPorts) &&
					hosts[j.hostIdx].OpenPorts[j.portIdx].Port == j.port.Port {
					hosts[j.hostIdx].OpenPorts[j.portIdx] = updated
				}
			}(j)
		}
		wg.Wait()
		if logger != nil {
			logger.Printf("http deep probe complete")
		}
	}

	if monitor != nil {
		go work()
	} else {
		work()
	}
}

// probeTLS performs a single TLS dial: success proves the port is open and lets us
// record the certificate subject. Returns false (with ProbeError set) on failure.
func probeTLS(ctx context.Context, ip string, port int, timeout time.Duration, pr *portResult) bool {
	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			InsecureSkipVerify: true, // inventory only; do not trust remote identity.
			ServerName:         ip,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		if pr.ProbeError == "" {
			pr.ProbeError = sanitizeOneLine(err.Error())
		}
		return false
	}
	defer conn.Close()
	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			pr.TLSSubject = sanitizeOneLine(state.PeerCertificates[0].Subject.String())
		}
	}
	return true
}

func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title")
	if start < 0 {
		return ""
	}
	start = strings.Index(lower[start:], ">")
	if start < 0 {
		return ""
	}
	titleStart := strings.Index(lower, "<title") + start + 1
	endRel := strings.Index(lower[titleStart:], "</title>")
	if endRel < 0 {
		return ""
	}
	return sanitizeOneLine(html.UnescapeString(body[titleStart : titleStart+endRel]))
}

func sanitizeOneLine(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.TrimSpace(value)
	if len(value) > maxFieldLen {
		// Trim on a rune boundary so we never emit a half-encoded UTF-8 sequence.
		trimmed := value[:maxFieldLen]
		for len(trimmed) > 0 && !utf8.ValidString(trimmed) {
			trimmed = trimmed[:len(trimmed)-1]
		}
		return trimmed
	}
	return value
}

func reverseLookupContext(ctx context.Context, ip string) string {
	if ctx == nil {
		ctx = context.Background()
	}
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// resolveHostname resolves a host's name through a layered fallback, since no
// single method covers every device:
//  1. reverse DNS (authoritative FQDN when a PTR record exists);
//  2. SMB/NTLM negotiation on 445/139 — reads the computer name the server
//     advertises in its NTLM challenge, which works even on modern Windows hosts
//     that have NetBIOS-over-TCP/IP disabled and no PTR record;
//  3. a NetBIOS node-status query (UDP/137) for older SMB/Windows devices.
func resolveHostname(ctx context.Context, ip string, openPorts []portResult, timeout time.Duration) string {
	if ctx == nil {
		ctx = context.Background()
	}
	dnsCtx, cancel := context.WithTimeout(ctx, minDuration(timeout, 500*time.Millisecond))
	defer cancel()
	if name := reverseLookupContext(dnsCtx, ip); name != "" {
		return name
	}

	hasPort := func(port int) bool {
		for _, pr := range openPorts {
			if pr.Port == port {
				return true
			}
		}
		return false
	}
	if hasPort(445) || hasPort(139) {
		if name := smbHostname(ctx, ip, minDuration(2*timeout, 2*time.Second)); name != "" {
			return name
		}
	}
	return netbiosName(ctx, ip, minDuration(timeout, 750*time.Millisecond))
}

// nbnsNodeStatusQuery is a fixed NBNS node-status request for the wildcard name
// "*" (the same request `nbtstat -A` issues). "*" encodes to 0x2A -> "CK" under
// NetBIOS first-level encoding, with the remaining 15 null bytes encoding to "AA".
var nbnsNodeStatusQuery = []byte{
	0x00, 0x00, // transaction id
	0x00, 0x00, // flags: standard query
	0x00, 0x01, // questions: 1
	0x00, 0x00, // answer RRs
	0x00, 0x00, // authority RRs
	0x00, 0x00, // additional RRs
	0x20,       // encoded name length: 32
	0x43, 0x4b, // "CK" -> 0x2A '*'
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x00,       // name terminator
	0x00, 0x21, // type: NBSTAT
	0x00, 0x01, // class: IN
}

// netbiosName queries UDP/137 for the host's NetBIOS name table and returns its
// unique computer name. Returns "" on any error or non-response.
func netbiosName(ctx context.Context, ip string, timeout time.Duration) string {
	return nbnsQuery(ctx, net.JoinHostPort(ip, "137"), timeout)
}

func nbnsQuery(ctx context.Context, addr string, timeout time.Duration) string {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(nbnsNodeStatusQuery); err != nil {
		return ""
	}
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		return ""
	}
	return parseNBNSName(resp[:n])
}

// parseNBNSName extracts the unique (non-group) computer name from an NBNS node-
// status response, preferring the Workstation Service entry (suffix 0x00).
func parseNBNSName(resp []byte) string {
	// Header(12) + answer name(34) + type(2) + class(2) + ttl(4) + rdlength(2) = 56,
	// after which RDATA begins with a one-byte name count, then 18 bytes per name.
	const rdataStart = 56
	if len(resp) <= rdataStart {
		return ""
	}
	if binary.BigEndian.Uint16(resp[6:8]) == 0 { // no answer records
		return ""
	}
	numNames := int(resp[rdataStart])
	offset := rdataStart + 1
	var fallback string
	for i := 0; i < numNames; i++ {
		if offset+18 > len(resp) {
			break
		}
		entry := resp[offset : offset+18]
		offset += 18
		name := strings.TrimRight(string(entry[0:15]), " \x00")
		suffix := entry[15]
		group := binary.BigEndian.Uint16(entry[16:18])&0x8000 != 0
		if group || name == "" {
			continue
		}
		if suffix == 0x00 {
			return sanitizeOneLine(name) // Workstation Service = computer name
		}
		if fallback == "" {
			fallback = name
		}
	}
	return sanitizeOneLine(fallback)
}

// ntlmType1 is a fixed NTLMSSP NEGOTIATE (Type 1) token. No credentials are sent;
// it merely elicits the server's CHALLENGE, whose target-info names the host.
var ntlmType1 = []byte{
	'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00,
	0x01, 0x00, 0x00, 0x00, // message type: 1
	0x07, 0x82, 0x08, 0x00, // flags 0x00088207 (unicode|oem|request-target|ntlm|always-sign|ext-sec)
	0x00, 0x00, 0x00, 0x00, // domain (len, maxlen)
	0x00, 0x00, 0x00, 0x00, // domain offset
	0x00, 0x00, 0x00, 0x00, // workstation (len, maxlen)
	0x00, 0x00, 0x00, 0x00, // workstation offset
}

var (
	smb2NegotiateReq    = buildSMB2Negotiate()
	smb2SessionSetupReq = buildSMB2SessionSetup()
)

// smbHostname opens an anonymous SMB2 session-setup negotiation on 445 and reads
// the computer name the server advertises in its NTLM challenge. Returns "" on
// any error. No credentials are submitted.
func smbHostname(ctx context.Context, ip string, timeout time.Duration) string {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "445"))
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(smb2NegotiateReq); err != nil {
		return ""
	}
	if _, err := readSMB2(conn); err != nil {
		return ""
	}
	if _, err := conn.Write(smb2SessionSetupReq); err != nil {
		return ""
	}
	resp, err := readSMB2(conn)
	if err != nil {
		return ""
	}
	return parseNTLMChallenge(resp)
}

// readSMB2 reads one message framed by the 4-byte Direct-TCP length prefix.
func readSMB2(conn net.Conn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	length := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if length <= 0 || length > 65535 {
		return nil, errors.New("invalid smb message length")
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// frameDirectTCP prepends the 4-byte Direct-TCP (port 445) length header.
func frameDirectTCP(payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	out[1] = byte(len(payload) >> 16)
	out[2] = byte(len(payload) >> 8)
	out[3] = byte(len(payload))
	copy(out[4:], payload)
	return out
}

// smb2Header builds a 64-byte SMB2 packet header for the given command.
func smb2Header(command uint16, messageID uint64) []byte {
	h := make([]byte, 64)
	copy(h[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(h[4:6], 64) // StructureSize
	binary.LittleEndian.PutUint16(h[12:14], command)
	binary.LittleEndian.PutUint16(h[14:16], 1) // CreditRequest
	binary.LittleEndian.PutUint64(h[24:32], messageID)
	return h
}

func buildSMB2Negotiate() []byte {
	body := make([]byte, 36)
	binary.LittleEndian.PutUint16(body[0:2], 36) // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], 2)  // DialectCount
	binary.LittleEndian.PutUint16(body[4:6], 1)  // SecurityMode: signing enabled
	dialects := make([]byte, 4)
	binary.LittleEndian.PutUint16(dialects[0:2], 0x0202) // SMB 2.0.2
	binary.LittleEndian.PutUint16(dialects[2:4], 0x0210) // SMB 2.1
	pkt := append(smb2Header(0x0000, 0), body...)
	pkt = append(pkt, dialects...)
	return frameDirectTCP(pkt)
}

func buildSMB2SessionSetup() []byte {
	const securityBufferOffset = 64 + 24 // header + fixed session-setup body
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 25) // StructureSize (24 + 1 convention)
	body[3] = 1                                  // SecurityMode: signing enabled
	binary.LittleEndian.PutUint16(body[12:14], securityBufferOffset)
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(ntlmType1)))
	pkt := append(smb2Header(0x0001, 1), body...) // SESSION_SETUP, message id 1
	pkt = append(pkt, ntlmType1...)
	return frameDirectTCP(pkt)
}

// parseNTLMChallenge locates the NTLMSSP CHALLENGE (Type 2) anywhere in an SMB2
// session-setup response and returns the advertised DNS computer name (FQDN),
// falling back to the NetBIOS computer name, from the challenge's target info.
func parseNTLMChallenge(resp []byte) string {
	idx := bytes.Index(resp, []byte("NTLMSSP\x00"))
	if idx < 0 {
		return ""
	}
	msg := resp[idx:]
	if len(msg) < 48 || binary.LittleEndian.Uint32(msg[8:12]) != 2 {
		return ""
	}
	tiLen := int(binary.LittleEndian.Uint16(msg[40:42]))
	tiOff := int(binary.LittleEndian.Uint32(msg[44:48]))
	if tiLen == 0 || tiOff < 0 || tiOff+tiLen > len(msg) {
		return ""
	}
	info := msg[tiOff : tiOff+tiLen]

	var nbName, dnsName string
	for off := 0; off+4 <= len(info); {
		avID := binary.LittleEndian.Uint16(info[off : off+2])
		avLen := int(binary.LittleEndian.Uint16(info[off+2 : off+4]))
		off += 4
		if avID == 0 { // MsvAvEOL
			break
		}
		if off+avLen > len(info) {
			break
		}
		switch avID {
		case 0x0001: // MsvAvNbComputerName
			nbName = utf16LE(info[off : off+avLen])
		case 0x0003: // MsvAvDnsComputerName (FQDN)
			dnsName = utf16LE(info[off : off+avLen])
		}
		off += avLen
	}
	if dnsName != "" {
		return sanitizeOneLine(dnsName)
	}
	return sanitizeOneLine(nbName)
}

// utf16LE decodes a little-endian UTF-16 byte slice to a string.
func utf16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	codes := make([]uint16, len(b)/2)
	for i := range codes {
		codes[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(codes))
}

// SNMP system-group object identifiers (BER-encoded), used for enrichment.
var (
	oidSysDescr = []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00} // 1.3.6.1.2.1.1.1.0
	oidSysName  = []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00} // 1.3.6.1.2.1.1.5.0
)

// snmpGet issues a single SNMP v2c GET for sysName.0 and sysDescr.0 over UDP/161
// using the given community. Returns empty strings on any error or non-response.
func snmpGet(ctx context.Context, ip, community string, timeout time.Duration) (sysName, sysDescr string) {
	req := buildSNMPGet(snmpRequestID(), community, [][]byte{oidSysName, oidSysDescr})
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(ip, "161"))
	if err != nil {
		return "", ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(req); err != nil {
		return "", ""
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return "", ""
	}
	vars := parseSNMPVarbinds(buf[:n])
	return vars[hex.EncodeToString(oidSysName)], vars[hex.EncodeToString(oidSysDescr)]
}

func snmpRequestID() int {
	return int(time.Now().UnixNano() & 0x7fffffff)
}

// buildSNMPGet encodes an SNMP v2c GetRequest for the given OIDs.
func buildSNMPGet(reqID int, community string, oids [][]byte) []byte {
	var varbinds []byte
	for _, oid := range oids {
		vb := asn1TLV(0x30, append(asn1TLV(0x06, oid), 0x05, 0x00)) // SEQUENCE { OID, NULL }
		varbinds = append(varbinds, vb...)
	}
	varbindList := asn1TLV(0x30, varbinds)

	var pduBody []byte
	pduBody = append(pduBody, asn1Int(reqID)...)
	pduBody = append(pduBody, asn1Int(0)...) // error-status
	pduBody = append(pduBody, asn1Int(0)...) // error-index
	pduBody = append(pduBody, varbindList...)
	pdu := asn1TLV(0xA0, pduBody) // GetRequest-PDU

	var msgBody []byte
	msgBody = append(msgBody, asn1Int(1)...) // version: v2c
	msgBody = append(msgBody, asn1TLV(0x04, []byte(community))...)
	msgBody = append(msgBody, pdu...)
	return asn1TLV(0x30, msgBody)
}

// parseSNMPVarbinds walks an SNMP response and returns a map of OID (hex) to the
// string value of each OCTET STRING var-bind.
func parseSNMPVarbinds(resp []byte) map[string]string {
	out := map[string]string{}
	_, msg, _, ok := readTLV(resp) // outer SEQUENCE
	if !ok {
		return out
	}
	_, _, rest, ok := readTLV(msg) // version
	if !ok {
		return out
	}
	_, _, rest, ok = readTLV(rest) // community
	if !ok {
		return out
	}
	_, pdu, _, ok := readTLV(rest) // GetResponse-PDU
	if !ok {
		return out
	}
	_, _, r, ok := readTLV(pdu) // request-id
	if !ok {
		return out
	}
	_, _, r, ok = readTLV(r) // error-status
	if !ok {
		return out
	}
	_, _, r, ok = readTLV(r) // error-index
	if !ok {
		return out
	}
	_, varbindList, _, ok := readTLV(r) // var-bind list SEQUENCE
	if !ok {
		return out
	}
	for len(varbindList) > 0 {
		var vb []byte
		_, vb, varbindList, ok = readTLV(varbindList)
		if !ok {
			break
		}
		oidTag, oid, afterOID, ok := readTLV(vb)
		if !ok || oidTag != 0x06 {
			continue
		}
		valTag, val, _, ok := readTLV(afterOID)
		if !ok {
			continue
		}
		if valTag == 0x04 { // OCTET STRING
			out[hex.EncodeToString(oid)] = sanitizeOneLine(string(val))
		}
	}
	return out
}

// readTLV decodes one BER tag-length-value triple, returning its tag, content,
// and the remaining bytes.
func readTLV(b []byte) (tag byte, content, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag = b[0]
	length := int(b[1])
	idx := 2
	if length&0x80 != 0 {
		numBytes := length & 0x7f
		if numBytes == 0 || numBytes > 4 || len(b) < 2+numBytes {
			return 0, nil, nil, false
		}
		length = 0
		for j := 0; j < numBytes; j++ {
			length = length<<8 | int(b[2+j])
		}
		idx = 2 + numBytes
	}
	if length < 0 || len(b) < idx+length {
		return 0, nil, nil, false
	}
	return tag, b[idx : idx+length], b[idx+length:], true
}

func asn1TLV(tag byte, content []byte) []byte {
	out := append([]byte{tag}, asn1Len(len(content))...)
	return append(out, content...)
}

func asn1Len(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func asn1Int(v int) []byte {
	if v == 0 {
		return asn1TLV(0x02, []byte{0x00})
	}
	var b []byte
	for x := v; x > 0; x >>= 8 {
		b = append([]byte{byte(x & 0xff)}, b...)
	}
	if b[0]&0x80 != 0 { // keep the value positive
		b = append([]byte{0x00}, b...)
	}
	return asn1TLV(0x02, b)
}

// guessDevice classifies a host from its open ports plus any free text (banners,
// HTTP headers, and SNMP sysDescr) gathered during enrichment.
func guessDevice(ports []portResult, extraText string) string {
	has := func(port int) bool {
		for _, p := range ports {
			if p.Port == port {
				return true
			}
		}
		return false
	}
	corpus := strings.ToLower(extraText)
	for _, p := range ports {
		corpus += " " + strings.ToLower(strings.Join([]string{p.Banner, p.HTTPServer, p.HTTPTitle, p.TLSSubject}, " "))
	}
	containsText := func(terms ...string) bool {
		for _, term := range terms {
			if strings.Contains(corpus, term) {
				return true
			}
		}
		return false
	}

	switch {
	case has(631) || has(9100) || containsText("printer", "jetdirect", "cups", "laserjet"):
		return "printer"
	case has(554) || containsText("camera", "rtsp", "hikvision", "axis", "dahua", "webcam"):
		return "camera"
	case has(2049) || has(548) || containsText("synology", "qnap", "truenas", "freenas", "diskstation"):
		return "nas"
	case has(5060) || has(5061) || containsText("asterisk", "voip", "grandstream", "polycom"):
		return "voip"
	case has(902) || containsText("vmware", "esxi", "proxmox", "hyper-v", "hypervisor"):
		return "vm"
	case containsText("cisco", "mikrotik", "routeros", "edgeos", "juniper", "aruba", "fortigate", "pfsense"):
		return "network"
	case has(135) || has(139) || has(445) || has(3389) || has(5985) || has(5986) || containsText("microsoft-iis", "windows server"):
		return "windows"
	case has(1433) || has(3306) || has(5432) || containsText("mariadb", "postgresql"):
		return "db"
	case has(22) || has(80) || has(443) || has(8080) || has(8443):
		return "linux/device"
	default:
		return "unknown"
	}
}

func writeArtifacts(report scanReport, cfg scanConfig) error {
	if cfg.JSONPath != "" {
		if err := writeJSON(cfg.JSONPath, report, cfg.MACFormat); err != nil {
			return err
		}
	}
	if cfg.CSVPath != "" {
		if err := writeCSV(cfg.CSVPath, report, cfg.MACFormat); err != nil {
			return err
		}
	}
	if cfg.WebhookURL != "" {
		if err := postJSONWebhook(cfg.WebhookURL, report, cfg.MACFormat); err != nil {
			return err
		}
	}
	return nil
}

func parseWebhookURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid webhook URL %q: %w", raw, err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return "", fmt.Errorf("webhook URL %q must use http or https", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("webhook URL %q must include a host", raw)
	}
	return raw, nil
}

func encodeJSONReport(w io.Writer, report scanReport, macFormat string) error {
	out := report
	out.Hosts = append([]hostResult(nil), report.Hosts...)
	for i := range out.Hosts {
		out.Hosts[i].MAC = formatMAC(out.Hosts[i].MAC, macFormat)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func writeJSON(path string, report scanReport, macFormat string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return encodeJSONReport(file, report, macFormat)
}

func postJSONWebhook(webhookURL string, report scanReport, macFormat string) error {
	var body bytes.Buffer
	if err := encodeJSONReport(&body, report, macFormat); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body.Bytes()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", appName+"/"+appVersion)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("webhook POST %s: %w", webhookURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook POST %s returned %s", webhookURL, resp.Status)
	}
	return nil
}

func writeCSV(path string, report scanReport, macFormat string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	w := csv.NewWriter(file)
	defer w.Flush()

	if err := w.Write([]string{"ip", "mac", "mac_vendor", "latency_ms", "hostname", "guess", "status", "arp_type", "arp_ifindex", "port", "service", "vendors", "banner", "http_status", "http_server", "http_title", "http_redirect", "tls_subject", "snmp_sysname", "snmp_sysdescr"}); err != nil {
		return err
	}
	for _, host := range report.Hosts {
		if len(host.OpenPorts) == 0 {
			if err := w.Write(hostCSVRow(host, portResult{}, macFormat)); err != nil {
				return err
			}
			continue
		}
		for _, port := range host.OpenPorts {
			if err := w.Write(hostCSVRow(host, port, macFormat)); err != nil {
				return err
			}
		}
	}
	return w.Error()
}

func hostCSVRow(host hostResult, port portResult, macFormat string) []string {
	portNum := ""
	service := ""
	if port.Port > 0 {
		portNum = strconv.Itoa(port.Port)
		service = port.Service
	}
	return []string{
		host.IP, formatMAC(host.MAC, macFormat), host.MACVendor, formatLatency(host.LatencyMS),
		host.Hostname, host.Guess, host.Status, host.ARPType, strconv.FormatUint(uint64(host.ARPIfIndex), 10),
		portNum, service, port.Vendors,
		port.Banner, port.HTTPStatus, port.HTTPServer, port.HTTPTitle, port.HTTPRedirect, port.TLSSubject,
		host.SysName, host.SysDescr,
	}
}

func formatLatency(ms int64) string {
	if ms < 0 {
		return ""
	}
	return strconv.FormatInt(ms, 10)
}

func formatLatencyDisplay(ms int64) string {
	if ms < 0 {
		return "-"
	}
	return strconv.FormatInt(ms, 10)
}

func formatStatusDisplay(status string) string {
	switch status {
	case "live":
		return "up"
	default:
		return status
	}
}

func formatPortsDisplay(ports []portResult) string {
	if len(ports) == 0 {
		return "-"
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p.Port)
	}
	return strings.Join(parts, ",")
}

func formatGuessDisplay(guess string) string {
	switch guess {
	case "linux/device":
		return "linux/dev"
	default:
		return guess
	}
}

func formatVendorDisplay(vendor string) string {
	if vendor == "" {
		return "-"
	}
	v := vendor
	for _, repl := range []struct{ old, new string }{
		{", Inc.", ""}, {", Inc", ""}, {" Inc.", ""},
		{" Corporation", " Corp"}, {" Systems", " Sys"},
	} {
		v = strings.ReplaceAll(v, repl.old, repl.new)
	}
	return truncDisplay(v, 24)
}

func formatNameDisplay(name string) string {
	return truncDisplay(orDash(name), 28)
}

func truncDisplay(s string, max int) string {
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

func formatARPInfo(host hostResult) string {
	return formatARPNeighborDisplay(host)
}

func formatARPState(host hostResult) string {
	if host.ARPType == "" && host.ARPIfIndex == 0 {
		return "-"
	}
	return arpNeighborState(host)
}

func formatARPAliasCell(host hostResult) string {
	alias := strings.TrimSpace(host.ARPIfAlias)
	if alias == "" {
		return "-"
	}
	return truncDisplay(alias, 24)
}

func formatARPAlias(host hostResult) string {
	alias := strings.TrimSpace(host.ARPIfAlias)
	if alias == "" {
		return "-"
	}
	return alias
}

func formatARPIndex(host hostResult) string {
	if host.ARPIfIndex == 0 {
		return "-"
	}
	return strconv.FormatUint(uint64(host.ARPIfIndex), 10)
}

func formatARPNeighborDisplay(host hostResult) string {
	if host.ARPType == "" && host.ARPIfIndex == 0 {
		return "-"
	}
	state := arpNeighborState(host)
	alias := strings.TrimSpace(host.ARPIfAlias)
	if host.ARPIfIndex > 0 {
		if alias != "" {
			return fmt.Sprintf("%s %s %d", state, alias, host.ARPIfIndex)
		}
		return fmt.Sprintf("%s %d", state, host.ARPIfIndex)
	}
	if alias != "" {
		return fmt.Sprintf("%s %s", state, alias)
	}
	return state
}

func arpNeighborState(host hostResult) string {
	if host.Status == "dead" {
		return "Unreachable"
	}
	switch host.ARPType {
	case "dynamic":
		if host.LatencyMS >= 0 || len(host.OpenPorts) > 0 {
			return "Reachable"
		}
		return "Stale"
	case "static":
		return "Permanent"
	case "invalid":
		return "Incomplete"
	default:
		if host.ARPType != "" {
			return host.ARPType
		}
		return "-"
	}
}

func hostWasLive(h hostResult) bool {
	switch h.Status {
	case "dead", "live", "arp":
		return true
	}
	if len(h.OpenPorts) > 0 || h.LatencyMS > 0 {
		return true
	}
	return false
}

func applyARPFromCache(host *hostResult, entry arpCacheEntry) {
	host.ARPType = entry.Kind
	host.ARPIfIndex = entry.IfIndex
	host.ARPIfAlias = entry.IfAlias
	if entry.MAC != "" {
		host.MAC = entry.MAC
	}
}

func fillARPFromCache(host *hostResult, targetCIDR string) {
	entry, ok := arpCacheEntryForIP(host.IP, targetCIDR)
	if !ok {
		return
	}
	applyARPFromCache(host, entry)
	if host.MAC != "" && host.MACVendor == "" {
		host.MACVendor = macVendor(host.MAC)
	}
}

func aipStatus(host hostResult) string {
	if len(host.OpenPorts) > 0 || host.LatencyMS >= 0 {
		return "up"
	}
	return "-"
}

func aipPing(host hostResult) string {
	return formatLatency(host.LatencyMS)
}

// printAIPTable renders results like Advanced IP Scanner: Status, Name, IP,
// Manufacturer, MAC Address, and Ping (ms).
func printAIPTable(w io.Writer, report scanReport, macFormat string) {
	fmt.Fprintf(w, "Target: %s  Hosts: %d  Duration: %s\n", report.Target, len(report.Hosts), report.CompletedAt.Sub(report.StartedAt).Round(time.Millisecond))
	if len(report.Hosts) == 0 {
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "Stat\tName\tIP\tMfg\tMAC\tMs")
	for _, host := range report.Hosts {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			aipStatus(host),
			formatNameDisplay(host.Hostname),
			host.IP,
			formatVendorDisplay(host.MACVendor),
			orDash(formatMAC(host.MAC, macFormat)),
			aipPing(host),
		)
	}
	_ = tw.Flush()
}

func printTable(w io.Writer, report scanReport, macFormat string) {
	fmt.Fprintf(w, "Target: %s  Hosts: %d  Duration: %s\n", report.Target, len(report.Hosts), report.CompletedAt.Sub(report.StartedAt).Round(time.Millisecond))
	if len(report.Hosts) == 0 {
		return
	}
	showVendor := false
	showStatus := false
	showARP := false
	for _, host := range report.Hosts {
		if host.MACVendor != "" {
			showVendor = true
		}
		if host.Status == "arp" {
			showStatus = true
		}
		if host.ARPType != "" {
			showARP = true
		}
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	header := []string{"IP", "MAC", "ms", "Name"}
	if showStatus {
		header = append(header, "Stat")
	}
	if showARP {
		header = append(header, "State", "Alias", "Index")
	}
	if showVendor {
		header = append(header, "Mfg")
	}
	header = append(header, "Type", "Ports")
	fmt.Fprintln(tw, strings.Join(header, "\t"))
	for _, host := range report.Hosts {
		openPorts := formatPortsDisplay(host.OpenPorts)
		row := []string{
			host.IP,
			orDash(formatMAC(host.MAC, macFormat)),
			formatLatencyDisplay(host.LatencyMS),
			formatNameDisplay(host.Hostname),
		}
		if showStatus {
			row = append(row, orDash(formatStatusDisplay(host.Status)))
		}
		if showARP {
			row = append(row, formatARPState(host), formatARPAliasCell(host), formatARPIndex(host))
		}
		if showVendor {
			row = append(row, formatVendorDisplay(host.MACVendor))
		}
		row = append(row, formatGuessDisplay(host.Guess), openPorts)
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	_ = tw.Flush()
}

func formatMAC(mac, format string) string {
	if mac == "" {
		return ""
	}
	hex := strings.ToLower(macHexDigits(mac))
	if len(hex) != 12 {
		return mac
	}
	sep := ":"
	switch format {
	case "none":
		return hex
	case "dash":
		sep = "-"
	}
	parts := []string{hex[0:2], hex[2:4], hex[4:6], hex[6:8], hex[8:10], hex[10:12]}
	return strings.Join(parts, sep)
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func lessIP(a, b string) bool {
	ai := net.ParseIP(a).To4()
	bi := net.ParseIP(b).To4()
	if ai == nil || bi == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if ai[i] != bi[i] {
			return ai[i] < bi[i]
		}
	}
	return false
}

func joinInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(value))
	}
	return strings.Join(parts, ",")
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
