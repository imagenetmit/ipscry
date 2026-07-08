package main

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

func discoverMDNS(ctx context.Context, iface *net.Interface, deadline time.Time) map[string]discoveryHit {
	hits := map[string]discoveryHit{}
	group := net.IPv4(224, 0, 0, 251)
	conn, err := listenMulticastUDP(iface, group, 5353)
	if err != nil {
		return hits
	}
	defer conn.Close()

	var mu sync.Mutex
	mergePacket := func(data []byte) {
		pkt, ok := parseDNSPacket(data)
		if !ok {
			return
		}
		local := map[string]discoveryHit{}
		for _, rec := range pkt.Records {
			switch rec.Type {
			case dnsTypeA:
				ip := dnsRecordIPv4(rec)
				if ip == "" {
					continue
				}
				name := strings.TrimSuffix(rec.Name, ".")
				hit := local[ip]
				hit.IP = ip
				hit.Sources = appendSource(hit.Sources, "mdns")
				if strings.HasSuffix(strings.ToLower(name), ".local") && hit.MDNSName == "" {
					hit.MDNSName = name
				}
				if strings.Contains(name, "._tcp.") || strings.Contains(name, "._udp.") {
					hit.MDNSServices = appendUniqueStrings(hit.MDNSServices, name)
				}
				local[ip] = hit
			case dnsTypePTR, dnsTypeSRV:
				name := dnsRecordName(data, rec)
				if name == "" {
					continue
				}
				if strings.Contains(name, "._tcp.") || strings.Contains(name, "._udp.") {
					for ip, hit := range local {
						hit.MDNSServices = appendUniqueStrings(hit.MDNSServices, name)
						local[ip] = hit
					}
				}
			}
		}
		if len(local) == 0 {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for ip, hit := range local {
			hits[ip] = mergeDiscoveryHit(hits[ip], hit)
		}
	}

	go readPacketsUntil(ctx, conn, deadline, func(_ net.Addr, data []byte) {
		mergePacket(data)
	})
	_ = sendMulticastUDP(iface, group, 5353, buildDNSQuery(0, "_services._dns-sd._udp.local", dnsTypePTR, false))
	waitUntil(ctx, deadline)
	return hits
}

func discoverMDNSFromPacket(data []byte) map[string]discoveryHit {
	hits := map[string]discoveryHit{}
	pkt, ok := parseDNSPacket(data)
	if !ok {
		return hits
	}
	for _, rec := range pkt.Records {
		if rec.Type != dnsTypeA {
			continue
		}
		ip := dnsRecordIPv4(rec)
		if ip == "" {
			continue
		}
		name := strings.TrimSuffix(rec.Name, ".")
		if !strings.HasSuffix(strings.ToLower(name), ".local") {
			continue
		}
		hit := hits[ip]
		hit.IP = ip
		hit.Sources = appendSource(hit.Sources, "mdns")
		hit.MDNSName = name
		hits[ip] = hit
	}
	return hits
}

func waitUntil(ctx context.Context, deadline time.Time) {
	if ctx == nil {
		ctx = context.Background()
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
