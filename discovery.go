package main

import (
	"context"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const defaultDiscoveryTimeout = 3 * time.Second

type discoveryConfig struct {
	enabled bool
	ssdp    bool
	mdns    bool
	llmnr   bool
	wsd     bool
	timeout time.Duration
}

type discoveryHit struct {
	IP           string
	Sources      []string
	MDNSName     string
	MDNSServices []string
	LLMNRName    string
	SSDPServer   string
	UPnPType     string
	UPnPLocation string
	UPnPFriendly string
	UPnPModel    string
	WSDTypes     []string
	WSDXAddrs    []string
	WSDScopes    []string
}

func parseDiscoveryInput(input string) (discoveryConfig, error) {
	input = strings.TrimSpace(strings.ToLower(input))
	cfg := discoveryConfig{timeout: defaultDiscoveryTimeout}
	if input == "" || input == "none" || input == "off" || input == "false" {
		return cfg, nil
	}
	parts := strings.Split(input, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch part {
		case "all", "on", "true":
			cfg.enabled = true
			cfg.ssdp, cfg.mdns, cfg.llmnr, cfg.wsd = true, true, true, true
		case "ssdp", "upnp":
			cfg.enabled = true
			cfg.ssdp = true
		case "mdns":
			cfg.enabled = true
			cfg.mdns = true
		case "llmnr":
			cfg.enabled = true
			cfg.llmnr = true
		case "wsd", "ws-discovery", "wsdiscovery":
			cfg.enabled = true
			cfg.wsd = true
		default:
			return cfg, fmtErrorDiscovery(part)
		}
	}
	return cfg, nil
}

func fmtErrorDiscovery(part string) error {
	return &discoveryParseError{part: part}
}

type discoveryParseError struct {
	part string
}

func (e *discoveryParseError) Error() string {
	return "unknown discovery protocol " + e.part + "; use none, all, ssdp, mdns, llmnr, or wsd"
}

func runLANDiscovery(ctx context.Context, targetCIDR string, cfg discoveryConfig, logger *log.Logger) map[string]discoveryHit {
	hits := map[string]discoveryHit{}
	if !cfg.enabled {
		return hits
	}
	iface, _, ipNet, ok := discoveryEligible(targetCIDR)
	if !ok {
		if logger != nil {
			logger.Printf("discovery skipped target=%s reason=not_local_segment", targetCIDR)
		}
		return hits
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()
	deadline := time.Now().Add(cfg.timeout)

	var mu sync.Mutex
	merge := func(partial map[string]discoveryHit) {
		mu.Lock()
		defer mu.Unlock()
		for ip, hit := range partial {
			if !ipInTarget(ip, ipNet) {
				continue
			}
			cur := hits[ip]
			cur.IP = ip
			cur = mergeDiscoveryHit(cur, hit)
			hits[ip] = cur
		}
	}

	var wg sync.WaitGroup
	if cfg.ssdp {
		wg.Add(1)
		go func() {
			defer wg.Done()
			merge(discoverSSDP(dctx, iface, deadline))
		}()
	}
	if cfg.mdns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			merge(discoverMDNS(dctx, iface, deadline))
		}()
	}
	if cfg.llmnr {
		wg.Add(1)
		go func() {
			defer wg.Done()
			merge(discoverLLMNR(dctx, iface, deadline))
		}()
	}
	if cfg.wsd {
		wg.Add(1)
		go func() {
			defer wg.Done()
			merge(discoverWSD(dctx, iface, deadline))
		}()
	}
	wg.Wait()

	if cfg.ssdp {
		fetchUPnPDescriptions(dctx, hits, minDuration(cfg.timeout, 1500*time.Millisecond))
	}
	if logger != nil {
		logger.Printf("discovery target=%s hits=%d timeout=%s", targetCIDR, len(hits), cfg.timeout)
	}
	return hits
}

func mergeDiscoveryHit(dst, src discoveryHit) discoveryHit {
	dst.Sources = appendSource(dst.Sources, src.Sources...)
	if dst.MDNSName == "" {
		dst.MDNSName = src.MDNSName
	}
	dst.MDNSServices = appendUniqueStrings(dst.MDNSServices, src.MDNSServices...)
	if dst.LLMNRName == "" {
		dst.LLMNRName = src.LLMNRName
	}
	if dst.SSDPServer == "" {
		dst.SSDPServer = src.SSDPServer
	}
	if dst.UPnPType == "" {
		dst.UPnPType = src.UPnPType
	}
	if dst.UPnPLocation == "" {
		dst.UPnPLocation = src.UPnPLocation
	}
	if dst.UPnPFriendly == "" {
		dst.UPnPFriendly = src.UPnPFriendly
	}
	if dst.UPnPModel == "" {
		dst.UPnPModel = src.UPnPModel
	}
	dst.WSDTypes = appendUniqueStrings(dst.WSDTypes, src.WSDTypes...)
	dst.WSDXAddrs = appendUniqueStrings(dst.WSDXAddrs, src.WSDXAddrs...)
	dst.WSDScopes = appendUniqueStrings(dst.WSDScopes, src.WSDScopes...)
	return dst
}

func appendSource(existing []string, sources ...string) []string {
	for _, src := range sources {
		existing = appendUniqueStrings(existing, src)
	}
	return existing
}

func appendUniqueStrings(existing []string, values ...string) []string {
	seen := map[string]bool{}
	for _, v := range existing {
		seen[strings.ToLower(v)] = true
	}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		key := strings.ToLower(v)
		if seen[key] {
			continue
		}
		seen[key] = true
		existing = append(existing, v)
	}
	sort.Strings(existing)
	return existing
}

func mergeDiscoveryHosts(byIP map[string][]portResult, hits map[string]discoveryHit, ipNet *net.IPNet) {
	for ip := range hits {
		if !ipInTarget(ip, ipNet) {
			continue
		}
		if _, ok := byIP[ip]; !ok {
			byIP[ip] = nil
		}
	}
}

func discoveryHostStatus(openPorts []portResult, hit discoveryHit, enrich enrichConfig, arpDeadByIP map[string]arpCacheEntry, ip string) string {
	if enrich.arpCache {
		if len(openPorts) > 0 {
			return "live"
		}
		if _, ok := arpDeadByIP[ip]; ok {
			return "arp"
		}
	}
	if enrich.discovery.enabled && hit.IP != "" && len(openPorts) == 0 {
		return "discovery"
	}
	return ""
}

func discoveryGuessText(hit discoveryHit) string {
	return strings.Join([]string{
		hit.MDNSName,
		strings.Join(hit.MDNSServices, " "),
		hit.LLMNRName,
		hit.SSDPServer,
		hit.UPnPType,
		hit.UPnPFriendly,
		hit.UPnPModel,
		strings.Join(hit.WSDTypes, " "),
		strings.Join(hit.WSDScopes, " "),
	}, " ")
}

func discoveryHostnameFallback(hostname string, hit discoveryHit) string {
	if hostname != "" {
		return hostname
	}
	if hit.MDNSName != "" {
		return strings.TrimSuffix(hit.MDNSName, ".local")
	}
	if hit.LLMNRName != "" {
		return hit.LLMNRName
	}
	return ""
}

func applyDiscoveryFields(host *hostResult, hit discoveryHit) {
	if host == nil || hit.IP == "" {
		return
	}
	host.DiscoverySources = append([]string(nil), hit.Sources...)
	host.MDNSName = hit.MDNSName
	host.MDNSServices = append([]string(nil), hit.MDNSServices...)
	host.LLMNRName = hit.LLMNRName
	host.SSDPServer = hit.SSDPServer
	host.UPnPType = hit.UPnPType
	host.UPnPLocation = hit.UPnPLocation
	host.UPnPFriendly = hit.UPnPFriendly
	host.UPnPModel = hit.UPnPModel
	host.WSDTypes = append([]string(nil), hit.WSDTypes...)
	host.WSDXAddrs = append([]string(nil), hit.WSDXAddrs...)
	host.WSDScopes = append([]string(nil), hit.WSDScopes...)
}

func hostAddrIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	switch v := addr.(type) {
	case *net.UDPAddr:
		return v.IP.String()
	case *net.IPAddr:
		return v.IP.String()
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err == nil {
			return host
		}
		return addr.String()
	}
}
