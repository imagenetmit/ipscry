package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

func TestParsePortsCommon(t *testing.T) {
	ports, err := parsePorts("common")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != len(defaultPorts) {
		t.Fatalf("got %d ports, want %d", len(ports), len(defaultPorts))
	}
}

func TestParsePortsDedupesAndSorts(t *testing.T) {
	ports, err := parsePorts("443,22,443,80")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{22, 80, 443}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("ports[%d]=%d, want %d", i, ports[i], want[i])
		}
	}
}

func TestParsePortsProfile(t *testing.T) {
	ports, err := parsePorts("web")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{80, 443, 631, 8000, 8008, 8080, 8443}
	if len(ports) != len(want) {
		t.Fatalf("got %d ports, want %d", len(ports), len(want))
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("ports[%d]=%d, want %d", i, ports[i], want[i])
		}
	}
}

func TestParsePortsRange(t *testing.T) {
	ports, err := parsePorts("8000-8002,80")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{80, 8000, 8001, 8002}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("ports[%d]=%d, want %d", i, ports[i], want[i])
		}
	}
}

func TestParsePortsRejectsBadRange(t *testing.T) {
	if _, err := parsePorts("8100-8000"); err == nil {
		t.Fatal("expected error for reversed range")
	}
}

func TestNormalizeScanArgsAllowsFlagsAfterTarget(t *testing.T) {
	flags, positional, err := normalizeScanArgs([]string{"192.168.1.0/24", "--timeout", "500ms", "--local"})
	if err != nil {
		t.Fatal(err)
	}
	if len(positional) != 1 || positional[0] != "192.168.1.0/24" {
		t.Fatalf("positional=%#v", positional)
	}
	want := []string{"--timeout", "500ms", "--local"}
	for i := range want {
		if flags[i] != want[i] {
			t.Fatalf("flags[%d]=%q, want %q", i, flags[i], want[i])
		}
	}
}

func TestExpandCIDRSkipsNetworkAndBroadcast(t *testing.T) {
	ips, err := expandCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 || ips[0] != "192.168.1.1" || ips[1] != "192.168.1.2" {
		t.Fatalf("unexpected ips: %#v", ips)
	}
}

func TestGuessDevicePrinter(t *testing.T) {
	got := guessDevice([]portResult{{Port: 9100, Service: "jetdirect"}}, "")
	if got != "printer" {
		t.Fatalf("guess=%q, want printer", got)
	}
}

func TestExtractTitle(t *testing.T) {
	got := extractTitle("<html><head><title>Office &amp; Lab</title></head></html>")
	if got != "Office & Lab" {
		t.Fatalf("title=%q", got)
	}
}

func TestScanLocalListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	result, ok := scanPort(nil, "127.0.0.1", port, time.Second)
	if !ok {
		t.Fatal("expected open port")
	}
	if result.port.Port != port {
		t.Fatalf("port=%d, want %d", result.port.Port, port)
	}
}

func TestProbeHTTPReturnsMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "ipscry-test")
		_, _ = w.Write([]byte("<html><head><title>Lab Device</title></head></html>"))
	}))
	defer server.Close()

	port := server.Listener.Addr().(*net.TCPAddr).Port
	pr := portResult{Port: port, Service: "unknown"}
	if !probeHTTP(context.Background(), "127.0.0.1", port, time.Second, &pr) {
		t.Fatalf("expected successful HTTP probe: %s", pr.ProbeError)
	}
	if pr.HTTPStatus != "200 OK" {
		t.Fatalf("status=%q, want 200 OK", pr.HTTPStatus)
	}
	if pr.HTTPTitle != "Lab Device" {
		t.Fatalf("title=%q, want Lab Device", pr.HTTPTitle)
	}
}

func TestWriteArtifacts(t *testing.T) {
	dir := t.TempDir()
	cfg := scanConfig{
		JSONPath: filepath.Join(dir, "scan.json"),
		CSVPath:  filepath.Join(dir, "scan.csv"),
	}
	report := scanReport{
		Scanner:     appName,
		Version:     appVersion,
		StartedAt:   time.Now().UTC(),
		CompletedAt: time.Now().UTC(),
		Target:      "127.0.0.1/32",
		Hosts: []hostResult{{
			IP:        "127.0.0.1",
			Guess:     "unknown",
			OpenPorts: []portResult{{Port: 80, Service: "http"}},
		}},
	}
	if err := writeArtifacts(report, cfg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"scan.json", "scan.csv"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestExpandCIDRRejectsLargeAndNonIPv4(t *testing.T) {
	cases := []struct {
		name  string
		cidr  string
		match string
	}{
		{"too large", "10.0.0.0/8", "larger than /16"},
		{"ipv6", "2001:db8::/64", "IPv4"},
		{"garbage", "not-a-cidr", "invalid CIDR"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := expandCIDR(tc.cidr)
			if err == nil {
				t.Fatalf("expected error for %q", tc.cidr)
			}
			if !strings.Contains(err.Error(), tc.match) {
				t.Fatalf("error %q does not contain %q", err, tc.match)
			}
		})
	}
}

func TestParseScanArgsValidation(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		match string
	}{
		{"zero timeout", []string{"192.168.1.0/24", "--timeout", "0s"}, "timeout"},
		{"low concurrency", []string{"192.168.1.0/24", "--concurrency", "0"}, "concurrency"},
		{"high concurrency", []string{"192.168.1.0/24", "--concurrency", "9000"}, "concurrency"},
		{"two targets", []string{"192.168.1.0/24", "10.0.0.0/24"}, "at most one"},
		{"local plus cidr", []string{"--local", "192.168.1.0/24"}, "either --local"},
		{"bad cidr", []string{"not-a-cidr"}, "invalid target CIDR"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseScanArgs(tc.args)
			if err == nil {
				t.Fatalf("expected error for %#v", tc.args)
			}
			if !strings.Contains(err.Error(), tc.match) {
				t.Fatalf("error %q does not contain %q", err, tc.match)
			}
		})
	}
}

func TestParseScanArgsExplicitTarget(t *testing.T) {
	cfg, err := parseScanArgs([]string{"192.168.1.0/24", "--concurrency", "64"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Target != "192.168.1.0/24" {
		t.Fatalf("target=%q", cfg.Target)
	}
	if cfg.Concurrency != 64 {
		t.Fatalf("concurrency=%d", cfg.Concurrency)
	}
}

func TestProgressDefaulting(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"on by default", []string{"192.168.1.0/24"}, true},
		{"off when json set", []string{"192.168.1.0/24", "--json", "out.json"}, false},
		{"off when log set", []string{"192.168.1.0/24", "--log", "out.log"}, false},
		{"explicit on overrides json", []string{"192.168.1.0/24", "--json", "out.json", "--progress"}, true},
		{"explicit off", []string{"192.168.1.0/24", "--progress=false"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseScanArgs(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Progress != tc.want {
				t.Fatalf("progress=%v, want %v", cfg.Progress, tc.want)
			}
		})
	}
}

func TestGuessDeviceBranches(t *testing.T) {
	cases := []struct {
		name  string
		ports []portResult
		extra string
		want  string
	}{
		{"camera by port", []portResult{{Port: 554}}, "", "camera"},
		{"camera by text", []portResult{{Port: 80, HTTPServer: "Hikvision-Webs"}}, "", "camera"},
		{"windows", []portResult{{Port: 445}}, "", "windows"},
		{"database", []portResult{{Port: 3306}}, "", "database"},
		{"linux", []portResult{{Port: 22}}, "", "linux_or_network_appliance"},
		{"unknown", []portResult{{Port: 53}}, "", "unknown"},
		{"network via snmp", []portResult{{Port: 22}}, "Cisco IOS Software, C3560", "network"},
		{"printer via snmp", []portResult{{Port: 80}}, "HP LaserJet MFP", "printer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := guessDevice(tc.ports, tc.extra); got != tc.want {
				t.Fatalf("guess=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestWriteCSVContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.csv")
	report := scanReport{
		Hosts: []hostResult{{
			IP:        "192.168.1.5",
			Hostname:  "printer.local",
			Guess:     "printer",
			OpenPorts: []portResult{{Port: 9100, Service: "jetdirect"}},
		}},
	}
	if err := writeCSV(path, report); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, want := range []string{
		"ip,hostname,guess,port,service",
		"192.168.1.5,printer.local,printer,9100,jetdirect",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("csv missing %q; got:\n%s", want, content)
		}
	}
}

func TestSanitizeOneLine(t *testing.T) {
	if got := sanitizeOneLine("one\r\ntwo  "); got != "one  two" {
		t.Fatalf("got %q", got)
	}

	long := strings.Repeat("a", 300)
	if got := sanitizeOneLine(long); len(got) != maxFieldLen {
		t.Fatalf("len=%d, want %d", len(got), maxFieldLen)
	}

	// A multibyte rune straddling the cut point must not be left half-encoded.
	multibyte := strings.Repeat("a", maxFieldLen-1) + "é"
	got := sanitizeOneLine(multibyte)
	if !utf8.ValidString(got) {
		t.Fatalf("truncation produced invalid UTF-8: %q", got)
	}
	if len(got) > maxFieldLen {
		t.Fatalf("len=%d exceeds max %d", len(got), maxFieldLen)
	}
}

// nbnsResponse builds a minimal NBNS node-status response advertising the given
// names, each as (15-char name, suffix, flags) triples.
func nbnsResponse(names []struct {
	name   string
	suffix byte
	flags  uint16
}) []byte {
	resp := make([]byte, 56)
	binary.BigEndian.PutUint16(resp[6:8], 1) // one answer record
	resp = append(resp, byte(len(names)))
	for _, n := range names {
		entry := make([]byte, 18)
		copy(entry[0:15], []byte(n.name))
		for i := len(n.name); i < 15; i++ {
			entry[i] = ' '
		}
		entry[15] = n.suffix
		binary.BigEndian.PutUint16(entry[16:18], n.flags)
		resp = append(resp, entry...)
	}
	return resp
}

func TestNBNSQueryConstant(t *testing.T) {
	// 12 header + 1 len + 32 encoded + 1 terminator + 2 type + 2 class = 50.
	if len(nbnsNodeStatusQuery) != 50 {
		t.Fatalf("query length=%d, want 50", len(nbnsNodeStatusQuery))
	}
}

func TestParseNBNSName(t *testing.T) {
	resp := nbnsResponse([]struct {
		name   string
		suffix byte
		flags  uint16
	}{
		{"WORKGROUP", 0x00, 0x8000},    // group; must be skipped
		{"DESKTOP-AB12", 0x20, 0x0400}, // unique server service; fallback
		{"DESKTOP-AB12", 0x00, 0x0400}, // unique workstation; preferred
	})
	if got := parseNBNSName(resp); got != "DESKTOP-AB12" {
		t.Fatalf("name=%q, want DESKTOP-AB12", got)
	}

	if got := parseNBNSName([]byte{0x00, 0x00}); got != "" {
		t.Fatalf("short response should yield empty, got %q", got)
	}
}

func TestNBNSQueryLocalResponder(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	canned := nbnsResponse([]struct {
		name   string
		suffix byte
		flags  uint16
	}{{"MYPC", 0x00, 0x0400}})

	go func() {
		buf := make([]byte, 512)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n == 0 {
			return
		}
		_, _ = pc.WriteTo(canned, addr)
	}()

	got := nbnsQuery(context.Background(), pc.LocalAddr().String(), time.Second)
	if got != "MYPC" {
		t.Fatalf("name=%q, want MYPC", got)
	}
}

// ntlmChallenge builds a minimal NTLMSSP CHALLENGE (Type 2) advertising the given
// NetBIOS and DNS computer names in its target-info block.
func ntlmChallenge(nb, dns string) []byte {
	enc := func(s string) []byte {
		u := utf16.Encode([]rune(s))
		b := make([]byte, len(u)*2)
		for i, r := range u {
			binary.LittleEndian.PutUint16(b[i*2:], r)
		}
		return b
	}
	var ti bytes.Buffer
	writeAV := func(id uint16, val []byte) {
		var h [4]byte
		binary.LittleEndian.PutUint16(h[0:2], id)
		binary.LittleEndian.PutUint16(h[2:4], uint16(len(val)))
		ti.Write(h[:])
		ti.Write(val)
	}
	if nb != "" {
		writeAV(0x0001, enc(nb))
	}
	if dns != "" {
		writeAV(0x0003, enc(dns))
	}
	ti.Write([]byte{0x00, 0x00, 0x00, 0x00}) // MsvAvEOL

	tiBytes := ti.Bytes()
	msg := make([]byte, 48)
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], 2) // CHALLENGE
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(tiBytes)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(tiBytes)))
	binary.LittleEndian.PutUint32(msg[44:48], 48) // target-info offset
	return append(msg, tiBytes...)
}

func TestParseNTLMChallenge(t *testing.T) {
	// Prefer the DNS computer name (FQDN), embedded in a larger response buffer.
	resp := append([]byte{0xFE, 'S', 'M', 'B', 0x00, 0x01}, ntlmChallenge("DESK01", "desk01.lan.example")...)
	if got := parseNTLMChallenge(resp); got != "desk01.lan.example" {
		t.Fatalf("name=%q, want desk01.lan.example", got)
	}

	// Fall back to the NetBIOS name when no DNS name is advertised.
	if got := parseNTLMChallenge(ntlmChallenge("DESK02", "")); got != "DESK02" {
		t.Fatalf("name=%q, want DESK02", got)
	}

	if got := parseNTLMChallenge([]byte("no ntlm token here")); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestSMBRequestFraming(t *testing.T) {
	for _, pkt := range [][]byte{smb2NegotiateReq, smb2SessionSetupReq} {
		if len(pkt) < 5 || pkt[0] != 0x00 {
			t.Fatalf("bad direct-tcp frame: %x", pkt[:5])
		}
		length := int(pkt[1])<<16 | int(pkt[2])<<8 | int(pkt[3])
		if length != len(pkt)-4 {
			t.Fatalf("length prefix %d != payload %d", length, len(pkt)-4)
		}
		if !bytes.Equal(pkt[4:8], []byte{0xFE, 'S', 'M', 'B'}) {
			t.Fatalf("missing SMB2 signature: %x", pkt[4:8])
		}
	}
}

// TestSMBHostnameLive exercises the real SMB path against a host you specify via
// IPSCRY_SMB_TARGET (e.g. a Windows box with 445 open). Skipped by default.
func TestSMBHostnameLive(t *testing.T) {
	target := os.Getenv("IPSCRY_SMB_TARGET")
	if target == "" {
		t.Skip("set IPSCRY_SMB_TARGET=<ip> to run the live SMB name test")
	}
	name := smbHostname(context.Background(), target, 2*time.Second)
	if name == "" {
		t.Fatalf("no SMB name resolved for %s", target)
	}
	t.Logf("resolved %s -> %s", target, name)
}

// snmpResponse builds an SNMP v2c GetResponse advertising the given OID (hex) to
// string-value pairs, reusing the production BER encoders.
func snmpResponse(values map[string]string) []byte {
	var varbinds []byte
	for oidHex, val := range values {
		oid, _ := hex.DecodeString(oidHex)
		vb := asn1TLV(0x30, append(asn1TLV(0x06, oid), asn1TLV(0x04, []byte(val))...))
		varbinds = append(varbinds, vb...)
	}
	varbindList := asn1TLV(0x30, varbinds)

	var pduBody []byte
	pduBody = append(pduBody, asn1Int(1)...) // request-id
	pduBody = append(pduBody, asn1Int(0)...) // error-status
	pduBody = append(pduBody, asn1Int(0)...) // error-index
	pduBody = append(pduBody, varbindList...)
	pdu := asn1TLV(0xA2, pduBody) // GetResponse-PDU

	var msgBody []byte
	msgBody = append(msgBody, asn1Int(1)...) // version: v2c
	msgBody = append(msgBody, asn1TLV(0x04, []byte("public"))...)
	msgBody = append(msgBody, pdu...)
	return asn1TLV(0x30, msgBody)
}

func TestSNMPGetRoundTrip(t *testing.T) {
	// Encode a GET, then build a response reusing the same encoders, and confirm
	// the var-bind parser recovers the values keyed by OID.
	req := buildSNMPGet(0x1234, "public", [][]byte{oidSysName, oidSysDescr})
	if _, _, _, ok := readTLV(req); !ok {
		t.Fatal("request is not valid BER")
	}

	resp := snmpResponse(map[string]string{
		hex.EncodeToString(oidSysName):  "switch01",
		hex.EncodeToString(oidSysDescr): "Cisco IOS",
	})
	vars := parseSNMPVarbinds(resp)
	if vars[hex.EncodeToString(oidSysName)] != "switch01" {
		t.Fatalf("sysName=%q", vars[hex.EncodeToString(oidSysName)])
	}
	if vars[hex.EncodeToString(oidSysDescr)] != "Cisco IOS" {
		t.Fatalf("sysDescr=%q", vars[hex.EncodeToString(oidSysDescr)])
	}
}

func TestSNMPGetLocalResponder(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	canned := snmpResponse(map[string]string{
		hex.EncodeToString(oidSysName):  "MYPRINTER",
		hex.EncodeToString(oidSysDescr): "HP LaserJet",
	})
	go func() {
		buf := make([]byte, 2048)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n == 0 {
			return
		}
		_, _ = pc.WriteTo(canned, addr)
	}()

	// snmpGet hardcodes :161; exercise the parse path against the responder's port
	// via the lower-level helpers, mirroring what snmpGet does after Read.
	conn, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write(buildSNMPGet(1, "public", [][]byte{oidSysName})); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	vars := parseSNMPVarbinds(buf[:n])
	if vars[hex.EncodeToString(oidSysName)] != "MYPRINTER" {
		t.Fatalf("sysName=%q, want MYPRINTER", vars[hex.EncodeToString(oidSysName)])
	}
}

func TestMACOUI(t *testing.T) {
	cases := map[string]string{
		"aa:bb:cc:dd:ee:ff": "AABBCC",
		"AA-BB-CC-DD-EE-FF": "AABBCC",
		"aabb.ccdd.eeff":    "AABBCC",
		"aa:bb":             "", // too few hex digits
		"":                  "",
	}
	for in, want := range cases {
		if got := macOUI(in); got != want {
			t.Fatalf("macOUI(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestParseMACVendor(t *testing.T) {
	if got := parseMACVendor([]byte(`[{"company":"Cisco Systems, Inc","country":"US"}]`)); got != "Cisco Systems, Inc" {
		t.Fatalf("got %q", got)
	}
	if got := parseMACVendor([]byte(`[]`)); got != "" {
		t.Fatalf("empty array should yield empty, got %q", got)
	}
	if got := parseMACVendor([]byte("not json")); got != "" {
		t.Fatalf("invalid json should yield empty, got %q", got)
	}
}

func TestMACVendorResolverDedupesByOUI(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`[{"company":"Acme Networks"}]`))
	}))
	defer server.Close()

	r := newMACVendorResolver()
	r.baseURL = server.URL + "/"
	r.minGap = 0 // disable throttle delay for the test

	v1 := r.lookup(context.Background(), "aa:bb:cc:11:22:33")
	v2 := r.lookup(context.Background(), "AA-BB-CC-44-55-66") // same OUI, different NIC
	if v1 != "Acme Networks" || v2 != "Acme Networks" {
		t.Fatalf("v1=%q v2=%q", v1, v2)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("api hits=%d, want 1 (deduped by OUI)", got)
	}
}

func TestMACVendorResolverNoMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent) // 204 = no match
	}))
	defer server.Close()

	r := newMACVendorResolver()
	r.baseURL = server.URL + "/"
	r.minGap = 0
	if v := r.lookup(context.Background(), "de:ad:be:ef:00:01"); v != "" {
		t.Fatalf("expected empty for 204, got %q", v)
	}
}

func TestPrintTableVendorColumn(t *testing.T) {
	withVendor := scanReport{Hosts: []hostResult{{
		IP: "192.168.1.5", Hostname: "pc", MACVendor: "Acme, Inc", Guess: "windows",
		OpenPorts: []portResult{{Port: 445, Service: "smb"}},
	}}}
	var buf bytes.Buffer
	printTable(&buf, withVendor)
	out := buf.String()
	if !strings.Contains(out, "Vendor") || !strings.Contains(out, "Acme, Inc") {
		t.Fatalf("expected Vendor column, got:\n%s", out)
	}

	// No vendor data anywhere -> column is omitted.
	noVendor := scanReport{Hosts: []hostResult{{
		IP: "192.168.1.5", Hostname: "pc", Guess: "windows",
		OpenPorts: []portResult{{Port: 445, Service: "smb"}},
	}}}
	buf.Reset()
	printTable(&buf, noVendor)
	if strings.Contains(buf.String(), "Vendor") {
		t.Fatalf("did not expect Vendor column, got:\n%s", buf.String())
	}
}

func TestLookupMACInvalid(t *testing.T) {
	if got := lookupMAC("not-an-ip"); got != "" {
		t.Fatalf("expected empty for invalid ip, got %q", got)
	}
}

func TestLessIP(t *testing.T) {
	if !lessIP("192.168.1.2", "192.168.1.10") {
		t.Fatal("expected .2 < .10")
	}
	if lessIP("192.168.1.10", "192.168.1.2") {
		t.Fatal("expected .10 not < .2")
	}
	if lessIP("10.0.0.1", "10.0.0.1") {
		t.Fatal("equal IPs are not less")
	}
}
