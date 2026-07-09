package main

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseDiscoveryInput(t *testing.T) {
	cfg, err := parseDiscoveryInput("none")
	if err != nil || cfg.enabled {
		t.Fatalf("none: cfg=%+v err=%v", cfg, err)
	}
	cfg, err = parseDiscoveryInput("all")
	if err != nil || !cfg.enabled || !cfg.ssdp || !cfg.mdns || !cfg.llmnr || !cfg.wsd {
		t.Fatalf("all: cfg=%+v err=%v", cfg, err)
	}
	cfg, err = parseDiscoveryInput("ssdp,mdns")
	if err != nil || !cfg.enabled || !cfg.ssdp || !cfg.mdns || cfg.llmnr || cfg.wsd {
		t.Fatalf("combo: cfg=%+v err=%v", cfg, err)
	}
	if _, err := parseDiscoveryInput("bogus"); err == nil {
		t.Fatal("expected error for bogus protocol")
	}
}

func TestParseScanArgsDiscoveryFlags(t *testing.T) {
	cfg, err := parseScanArgs([]string{"192.168.1.0/24", "-d", "all", "-D", "1500ms"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Discovery.enabled || !cfg.Discovery.ssdp || cfg.DiscoveryTimeout != 1500*time.Millisecond {
		t.Fatalf("cfg=%+v timeout=%s", cfg.Discovery, cfg.DiscoveryTimeout)
	}
}

func TestNormalizeScanArgsDiscoveryShortFlags(t *testing.T) {
	flags, positional, err := normalizeScanArgs([]string{"192.168.1.0/24", "-d", "ssdp", "-D", "2s"})
	if err != nil {
		t.Fatal(err)
	}
	if len(positional) != 1 || positional[0] != "192.168.1.0/24" {
		t.Fatalf("positional=%#v", positional)
	}
	want := []string{"--discovery", "ssdp", "--discovery-timeout", "2s"}
	for i := range want {
		if flags[i] != want[i] {
			t.Fatalf("flags[%d]=%q want %q", i, flags[i], want[i])
		}
	}
}

func TestParseSSDPResponse(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n" +
		"LOCATION: http://192.168.1.10:49152/description.xml\r\n" +
		"SERVER: UPnP/1.0 Samsung AllShare/1.0\r\n" +
		"ST: upnp:rootdevice\r\n" +
		"USN: uuid:device-1::upnp:rootdevice\r\n\r\n"
	server, st, location, usn := parseSSDPResponse([]byte(raw))
	if server == "" || st == "" || location == "" || usn == "" {
		t.Fatalf("server=%q st=%q location=%q usn=%q", server, st, location, usn)
	}
}

func TestParseUPnPDescription(t *testing.T) {
	body := `<root><device><friendlyName>Living Room TV</friendlyName><modelName>UN55</modelName></device></root>`
	friendly, model := parseUPnPDescription([]byte(body))
	if friendly != "Living Room TV" || model != "UN55" {
		t.Fatalf("friendly=%q model=%q", friendly, model)
	}
}

func TestParseWSDResponse(t *testing.T) {
	raw := `<?xml version="1.0" encoding="utf-8"?>` +
		`<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">` +
		`<soap:Body><wsd:ProbeMatches xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">` +
		`<wsd:ProbeMatch><wsd:Types>dn:NetworkVideoTransmitter</wsd:Types>` +
		`<wsd:XAddrs>http://192.168.1.20/onvif/device_service</wsd:XAddrs>` +
		`<wsd:Scopes>onvif://www.onvif.org/Profile/Streaming</wsd:Scopes>` +
		`</wsd:ProbeMatch></wsd:ProbeMatches></soap:Body></soap:Envelope>`
	types, xaddrs, scopes := parseWSDResponse([]byte(raw))
	if len(types) == 0 || len(xaddrs) == 0 || len(scopes) == 0 {
		t.Fatalf("types=%v xaddrs=%v scopes=%v", types, xaddrs, scopes)
	}
}

func TestDiscoverMDNSFromPacket(t *testing.T) {
	pkt := buildDNSResponseA("printer.local", [4]byte{192, 168, 1, 50})
	hits := discoverMDNSFromPacket(pkt)
	hit := hits["192.168.1.50"]
	if hit.MDNSName != "printer.local" || !containsString(hit.Sources, "mdns") {
		t.Fatalf("hit=%+v", hit)
	}
}

func TestDiscoverLLMNRFromPacket(t *testing.T) {
	pkt := buildDNSResponseA("DESKTOP-PC", [4]byte{192, 168, 1, 25})
	hits := discoverLLMNRFromPacket(pkt)
	hit := hits["192.168.1.25"]
	if hit.LLMNRName != "DESKTOP-PC" || !containsString(hit.Sources, "llmnr") {
		t.Fatalf("hit=%+v", hit)
	}
}

func buildDNSResponseA(name string, ip [4]byte) []byte {
	var pkt []byte
	pkt = append(pkt, 0, 0, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0)
	pkt = append(pkt, encodeDNSName(name)...)
	pkt = append(pkt, 0, byte(dnsTypeA), 0, 1)
	pkt = append(pkt, 0xc0, 0x0c)
	pkt = append(pkt, 0, byte(dnsTypeA), 0, 1, 0, 0, 0, 0, 0, 4)
	pkt = append(pkt, ip[:]...)
	return pkt
}

func TestMergeDiscoveryHosts(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	byIP := map[string][]portResult{"192.168.1.10": {{Port: 80, Service: "http"}}}
	hits := map[string]discoveryHit{
		"192.168.1.10": {IP: "192.168.1.10", Sources: []string{"ssdp"}},
		"192.168.1.99": {IP: "192.168.1.99", Sources: []string{"mdns"}, MDNSName: "tv.local"},
		"10.0.0.5":     {IP: "10.0.0.5", Sources: []string{"mdns"}},
	}
	mergeDiscoveryHosts(byIP, hits, ipNet)
	if len(byIP["192.168.1.10"]) != 1 {
		t.Fatal("existing host ports changed")
	}
	if _, ok := byIP["192.168.1.99"]; !ok {
		t.Fatal("expected discovery-only host in byIP")
	}
	if _, ok := byIP["10.0.0.5"]; ok {
		t.Fatal("out-of-target discovery host should be excluded")
	}
}

func TestEnrichHostDiscoveryMetadata(t *testing.T) {
	ctx := context.Background()
	discoveryByIP := map[string]discoveryHit{
		"192.168.1.40": {
			IP:           "192.168.1.40",
			Sources:      []string{"ssdp", "mdns"},
			MDNSName:     "office-printer.local",
			SSDPServer:   "HP UPnP Device",
			UPnPFriendly: "HP LaserJet",
			UPnPModel:    "M404",
		},
	}
	enrich := enrichConfig{discovery: discoveryConfig{enabled: true}}
	host := enrichHost(ctx, "192.168.1.40", nil, enrich, 250*time.Millisecond, nil, nil, discoveryByIP, -1)
	if host.Hostname != "office-printer" {
		t.Fatalf("hostname=%q", host.Hostname)
	}
	if host.Status != "discovery" {
		t.Fatalf("status=%q", host.Status)
	}
	if host.Guess != "printer" {
		t.Fatalf("guess=%q", host.Guess)
	}
	if host.SSDPServer == "" || host.UPnPFriendly == "" {
		t.Fatalf("host=%+v", host)
	}
}

func TestWriteCSVIncludesDiscoveryFields(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/scan.csv"
	report := scanReport{Hosts: []hostResult{{
		IP:               "192.168.1.40",
		Hostname:         "office-printer",
		Guess:            "printer",
		Status:           "discovery",
		DiscoverySources: []string{"mdns", "ssdp"},
		MDNSName:         "office-printer.local",
		MDNSServices:     []string{"_ipp._tcp.local"},
		SSDPServer:       "HP UPnP Device",
		UPnPFriendly:     "HP LaserJet",
	}}}
	if err := writeCSV(path, report, "colon"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, want := range []string{
		"discovery_sources,mdns_name,mdns_services,llmnr_name,ssdp_server",
		"mdns;ssdp,office-printer.local,_ipp._tcp.local,,HP UPnP Device",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("csv missing %q; got:\n%s", want, content)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
