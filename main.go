package main

import (
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
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
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
)

// appVersion is overridable at build time:
//
//	go build -ldflags "-X main.appVersion=1.2.3"
var appVersion = "0.1.0"

var defaultPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
	515, 554, 587, 631, 993, 995, 1433, 1883, 3306, 3389,
	5432, 5900, 8000, 8008, 8080, 8443, 8883, 9100,
}

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
	Local         bool
	Ports         []int
	Timeout       time.Duration
	Concurrency   int
	Progress      bool
	SNMPCommunity string
	MACVendor     bool
	JSONPath      string
	CSVPath       string
	LogPath       string
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
	IP        string       `json:"ip"`
	Hostname  string       `json:"hostname,omitempty"`
	MAC       string       `json:"mac,omitempty"`
	MACVendor string       `json:"mac_vendor,omitempty"`
	SysName   string       `json:"snmp_sysname,omitempty"`
	SysDescr  string       `json:"snmp_sysdescr,omitempty"`
	OpenPorts []portResult `json:"open_ports"`
	Guess     string       `json:"guess"`
}

type portResult struct {
	Port       int    `json:"port"`
	Service    string `json:"service"`
	Banner     string `json:"banner,omitempty"`
	HTTPStatus string `json:"http_status,omitempty"`
	HTTPServer string `json:"http_server,omitempty"`
	HTTPTitle  string `json:"http_title,omitempty"`
	TLSSubject string `json:"tls_subject,omitempty"`
	ProbeError string `json:"probe_error,omitempty"`
}

type portScanResult struct {
	ip   string
	port portResult
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		printUsage(stdout)
		return nil
	}
	if args[0] == "version" || args[0] == "--version" {
		fmt.Fprintf(stdout, "%s %s\n", appName, appVersion)
		return nil
	}
	if args[0] != "scan" {
		return fmt.Errorf("unknown command %q", args[0])
	}
	if len(args) > 1 && (args[1] == "-h" || args[1] == "--help") {
		printUsage(stdout)
		return nil
	}

	cfg, err := parseScanArgs(args[1:])
	if err != nil {
		return err
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
	if cfg.Progress {
		progress = stderr
	}
	enrich := enrichConfig{snmpCommunity: cfg.SNMPCommunity}
	if cfg.MACVendor {
		enrich.macResolver = newMACVendorResolver()
	}
	hosts := scanNetwork(ctx, ips, cfg.Ports, cfg.Timeout, cfg.Concurrency, enrich, logger, progress)
	completed := time.Now().UTC()

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

	logger.Printf("completed_at=%s discovered_hosts=%d duration=%s", completed.Format(time.RFC3339), len(hosts), completed.Sub(started))
	printTable(stdout, report)
	return nil
}

func parseScanArgs(args []string) (scanConfig, error) {
	cfg := scanConfig{
		Ports:       append([]int(nil), defaultPorts...),
		Timeout:     750 * time.Millisecond,
		Concurrency: 128,
	}

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	local := fs.Bool("local", false, "scan active local /24")
	ports := fs.String("ports", "common", "profile (common|web|windows|db), list, or ranges")
	timeout := fs.Duration("timeout", cfg.Timeout, "TCP connect timeout")
	concurrency := fs.Int("concurrency", cfg.Concurrency, "maximum concurrent port checks")
	progress := fs.Bool("progress", false, "print scan progress to stderr")
	snmpCommunity := fs.String("snmp-community", "public", "SNMP v2c community for enrichment (empty to disable)")
	macVendor := fs.Bool("mac-vendor", false, "look up MAC vendor via macvendorlookup.com (local subnet only)")
	jsonPath := fs.String("json", "", "write JSON results to path")
	csvPath := fs.String("csv", "", "write CSV results to path")
	logPath := fs.String("log", "", "write audit log to path")

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
	cfg.Local = *local
	cfg.SNMPCommunity = *snmpCommunity
	cfg.MACVendor = *macVendor
	cfg.JSONPath = defaultPathIfEmpty(*jsonPath, "scan.json")
	cfg.CSVPath = defaultPathIfEmpty(*csvPath, "scan.csv")
	cfg.LogPath = defaultPathIfEmpty(*logPath, "scan.log")

	// Progress defaults on for interactive use, but stays off when an output path
	// was explicitly requested (typically unattended/NinjaRMM runs). An explicit
	// --progress always wins.
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if set["progress"] {
		cfg.Progress = *progress
	} else {
		cfg.Progress = !(set["json"] || set["csv"] || set["log"])
	}

	if cfg.Timeout <= 0 {
		return cfg, errors.New("timeout must be greater than zero")
	}
	if cfg.Concurrency < 1 || cfg.Concurrency > 2048 {
		return cfg, errors.New("concurrency must be between 1 and 2048")
	}

	switch {
	case len(positional) > 1:
		return cfg, errors.New("scan accepts at most one target CIDR")
	case len(positional) == 1:
		if cfg.Local {
			return cfg, errors.New("provide either --local or an explicit CIDR, not both")
		}
		cfg.Target = positional[0]
	default:
		// No target given (with or without --local): scan the active local /24.
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

func normalizeScanArgs(args []string) ([]string, []string, error) {
	valueFlags := map[string]bool{
		"--ports": true, "--timeout": true, "--concurrency": true,
		"--snmp-community": true, "--json": true, "--csv": true, "--log": true,
	}
	var flags []string
	var positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--") {
			flags = append(flags, arg)
			name := arg
			if idx := strings.Index(arg, "="); idx >= 0 {
				name = arg[:idx]
			}
			if valueFlags[name] && !strings.Contains(arg, "=") {
				if i+1 >= len(args) {
					return nil, nil, fmt.Errorf("missing value for %s", arg)
				}
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positional = append(positional, arg)
	}
	return flags, positional, nil
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `%s %s

Usage:
  ipscry scan --local [options]
  ipscry scan 192.168.1.0/24 [options]
  ipscry version

Options:
  --ports common|web|windows|db | 22,80,443 | 8000-8100
  --timeout 750ms
  --concurrency 128
  --progress
  --snmp-community public
  --mac-vendor
  --json PATH
  --csv PATH
  --log PATH
`, appName, appVersion)
}

// portProfiles are named port sets selectable via --ports <name>.
var portProfiles = map[string][]int{
	"common":  defaultPorts,
	"web":     {80, 443, 631, 8000, 8008, 8080, 8443},
	"windows": {135, 139, 445, 1433, 3389, 5985, 5986},
	"db":      {1433, 3306, 5432},
}

func parsePorts(input string) ([]int, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return append([]int(nil), defaultPorts...), nil
	}
	if profile, ok := portProfiles[strings.ToLower(input)]; ok {
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

func defaultPathIfEmpty(path string, name string) string {
	if strings.TrimSpace(path) != "" {
		return path
	}
	return filepath.Join(defaultArtifactDir(), name)
}

func defaultArtifactDir() string {
	if runtime.GOOS == "windows" {
		if programData := os.Getenv("ProgramData"); programData != "" {
			return filepath.Join(programData, "ipscry")
		}
		return `C:\ProgramData\ipscry`
	}
	return "ipscry-output"
}

func configureLog(path string) (*log.Logger, func(), error) {
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
	macResolver   *macVendorResolver // nil when MAC/vendor lookup is disabled
}

func scanNetwork(ctx context.Context, ips []string, ports []int, timeout time.Duration, concurrency int, enrich enrichConfig, logger *log.Logger, progress io.Writer) []hostResult {
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

	// Optional periodic progress to stderr while results stream in.
	stopProgress := make(chan struct{})
	if progress != nil && total > 0 {
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stopProgress:
					return
				case <-ticker.C:
					fmt.Fprintf(progress, "\rscanning %d/%d ports...", atomic.LoadInt64(&scanned), total)
				}
			}
		}()
	}

	byIP := map[string][]portResult{}
	for result := range results {
		byIP[result.ip] = append(byIP[result.ip], result.port)
		logger.Printf("open ip=%s port=%d service=%s", result.ip, result.port.Port, result.port.Service)
	}
	close(stopProgress)
	if progress != nil && total > 0 {
		fmt.Fprintf(progress, "\rscanned %d/%d ports        \n", atomic.LoadInt64(&scanned), total)
	}

	var hosts []hostResult
	var hostMu sync.Mutex
	var hostWorkers sync.WaitGroup
	for ip, openPorts := range byIP {
		ip := ip
		openPorts := openPorts
		sort.Slice(openPorts, func(i, j int) bool { return openPorts[i].Port < openPorts[j].Port })
		hostWorkers.Add(1)
		go func() {
			defer hostWorkers.Done()
			hostname := resolveHostname(ctx, ip, openPorts, timeout)
			var sysName, sysDescr string
			if enrich.snmpCommunity != "" {
				sysName, sysDescr = snmpGet(ctx, ip, enrich.snmpCommunity, minDuration(timeout, time.Second))
			}
			if hostname == "" {
				hostname = sysName
			}
			var mac, vendor string
			if enrich.macResolver != nil {
				if mac = lookupMAC(ip); mac != "" {
					vendor = enrich.macResolver.lookup(ctx, mac)
				}
			}
			host := hostResult{
				IP:        ip,
				Hostname:  hostname,
				MAC:       mac,
				MACVendor: vendor,
				SysName:   sysName,
				SysDescr:  sysDescr,
				OpenPorts: openPorts,
				Guess:     guessDevice(openPorts, sysDescr),
			}
			hostMu.Lock()
			hosts = append(hosts, host)
			hostMu.Unlock()
		}()
	}
	hostWorkers.Wait()
	sort.Slice(hosts, func(i, j int) bool {
		return lessIP(hosts[i].IP, hosts[j].IP)
	})
	return hosts
}

func scanPort(ctx context.Context, ip string, port int, timeout time.Duration) (portScanResult, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	info := portCatalog[port]
	pr := portResult{Port: port, Service: serviceName(port)}

	// HTTP ports: the HTTP client performs its own dial. A response (any status)
	// proves the port is open and yields the richest metadata in one round-trip.
	if info.http {
		if probeHTTP(ctx, ip, port, timeout, &pr) {
			return portScanResult{ip: ip, port: pr}, true
		}
		// Probe failed; pr.ProbeError is retained and we fall through to a plain
		// TCP check so an open-but-not-HTTP port is still reported.
	}

	// TLS-only ports: dial with TLS directly so the single connection both proves
	// the port is open and surfaces the certificate subject.
	if info.tls && !info.http {
		if probeTLS(ctx, ip, port, timeout, &pr) {
			return portScanResult{ip: ip, port: pr}, true
		}
	}

	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return portScanResult{}, false
	}
	defer conn.Close()

	if info.banner {
		_ = conn.SetReadDeadline(time.Now().Add(minDuration(timeout, 300*time.Millisecond)))
		buf := make([]byte, 256)
		if n, err := conn.Read(buf); err == nil && n > 0 {
			pr.Banner = sanitizeOneLine(string(buf[:n]))
		}
	}

	return portScanResult{ip: ip, port: pr}, true
}

func serviceName(port int) string {
	if info, ok := portCatalog[port]; ok {
		return info.service
	}
	return "unknown"
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
	pr.HTTPServer = sanitizeOneLine(resp.Header.Get("Server"))
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		pr.TLSSubject = sanitizeOneLine(resp.TLS.PeerCertificates[0].Subject.String())
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	pr.HTTPTitle = extractTitle(string(body))
	return true
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

// macVendorResolver looks up the vendor for a MAC's OUI via macvendorlookup.com.
// It dedupes by OUI (caching results) and serializes requests with a minimum gap
// so the free API is queried responsibly — one request per unique vendor prefix.
type macVendorResolver struct {
	client  *http.Client
	baseURL string
	minGap  time.Duration

	mu      sync.Mutex
	cache   map[string]string // OUI (6 hex) -> vendor
	lastReq time.Time
}

func newMACVendorResolver() *macVendorResolver {
	return &macVendorResolver{
		client:  &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}},
		baseURL: "https://www.macvendorlookup.com/api/v2/",
		minGap:  time.Second,
		cache:   map[string]string{},
	}
}

// lookup returns the vendor for the given MAC, or "" if unknown. The lock is held
// across the request so lookups are both deduped and rate-limited.
func (r *macVendorResolver) lookup(ctx context.Context, mac string) string {
	oui := macOUI(mac)
	if oui == "" {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if vendor, ok := r.cache[oui]; ok {
		return vendor
	}
	if wait := r.minGap - time.Since(r.lastReq); wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ""
		}
	}
	r.lastReq = time.Now()
	vendor := r.fetch(ctx, oui)
	r.cache[oui] = vendor // cache negatives too, so we don't re-query a dead OUI
	return vendor
}

func (r *macVendorResolver) fetch(ctx context.Context, oui string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+oui, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", appName+"/"+appVersion)
	resp, err := r.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { // 204 No Content = no match
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return parseMACVendor(body)
}

// parseMACVendor extracts the company name from the API's JSON array response.
func parseMACVendor(body []byte) string {
	var entries []struct {
		Company string `json:"company"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return ""
	}
	for _, e := range entries {
		if e.Company != "" {
			return sanitizeOneLine(e.Company)
		}
	}
	return ""
}

// macOUI returns the 24-bit OUI (first six hex digits, uppercased) of a MAC, or
// "" if the input has fewer than six hex digits.
func macOUI(mac string) string {
	var sb strings.Builder
	for _, r := range mac {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'F':
			sb.WriteRune(r)
		case r >= 'a' && r <= 'f':
			sb.WriteRune(r - 32) // uppercase
		}
		if sb.Len() == 6 {
			return sb.String()
		}
	}
	return ""
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
		return "hypervisor"
	case containsText("cisco", "mikrotik", "routeros", "edgeos", "juniper", "aruba", "fortigate", "pfsense"):
		return "network"
	case has(135) || has(139) || has(445) || has(3389) || has(5985) || has(5986) || containsText("microsoft-iis", "windows server"):
		return "windows"
	case has(1433) || has(3306) || has(5432) || containsText("mariadb", "postgresql"):
		return "database"
	case has(22) || has(80) || has(443) || has(8080) || has(8443):
		return "linux_or_network_appliance"
	default:
		return "unknown"
	}
}

func writeArtifacts(report scanReport, cfg scanConfig) error {
	if err := writeJSON(cfg.JSONPath, report); err != nil {
		return err
	}
	if err := writeCSV(cfg.CSVPath, report); err != nil {
		return err
	}
	return nil
}

func writeJSON(path string, report scanReport) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func writeCSV(path string, report scanReport) error {
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

	if err := w.Write([]string{"ip", "hostname", "guess", "port", "service", "banner", "http_status", "http_server", "http_title", "tls_subject", "snmp_sysname", "snmp_sysdescr", "mac", "mac_vendor"}); err != nil {
		return err
	}
	for _, host := range report.Hosts {
		for _, port := range host.OpenPorts {
			if err := w.Write([]string{
				host.IP, host.Hostname, host.Guess, strconv.Itoa(port.Port), port.Service,
				port.Banner, port.HTTPStatus, port.HTTPServer, port.HTTPTitle, port.TLSSubject,
				host.SysName, host.SysDescr, host.MAC, host.MACVendor,
			}); err != nil {
				return err
			}
		}
	}
	return w.Error()
}

func printTable(w io.Writer, report scanReport) {
	fmt.Fprintf(w, "Target: %s  Hosts: %d  Duration: %s\n", report.Target, len(report.Hosts), report.CompletedAt.Sub(report.StartedAt).Round(time.Millisecond))
	if len(report.Hosts) == 0 {
		return
	}
	// Only show the Vendor column when MAC lookup actually populated it.
	showVendor := false
	for _, host := range report.Hosts {
		if host.MACVendor != "" {
			showVendor = true
			break
		}
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if showVendor {
		fmt.Fprintln(tw, "IP\tHostname\tVendor\tGuess\tOpen Ports")
	} else {
		fmt.Fprintln(tw, "IP\tHostname\tGuess\tOpen Ports")
	}
	for _, host := range report.Hosts {
		var open []string
		for _, port := range host.OpenPorts {
			open = append(open, fmt.Sprintf("%d/%s", port.Port, port.Service))
		}
		hostname := orDash(host.Hostname)
		if showVendor {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", host.IP, hostname, orDash(host.MACVendor), host.Guess, strings.Join(open, ","))
		} else {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", host.IP, hostname, host.Guess, strings.Join(open, ","))
		}
	}
	_ = tw.Flush()
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
