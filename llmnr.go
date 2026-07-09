package main

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

func discoverLLMNR(ctx context.Context, iface *net.Interface, deadline time.Time) map[string]discoveryHit {
	hits := map[string]discoveryHit{}
	group := net.IPv4(224, 0, 0, 252)
	conn, err := listenMulticastUDP(iface, group, 5355)
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
		namesByIP := map[string]string{}
		for _, rec := range pkt.Records {
			if rec.Type != dnsTypeA && rec.Type != dnsTypeAAAA {
				continue
			}
			ip := dnsRecordIPv4(rec)
			if ip == "" && rec.Type == dnsTypeAAAA {
				ip = dnsRecordIPv6(rec)
			}
			if ip == "" {
				continue
			}
			name := strings.TrimSuffix(rec.Name, ".")
			if name == "" {
				continue
			}
			namesByIP[ip] = name
		}
		mu.Lock()
		defer mu.Unlock()
		for ip, name := range namesByIP {
			hit := hits[ip]
			hit.IP = ip
			hit.Sources = appendSource(hit.Sources, "llmnr")
			if hit.LLMNRName == "" {
				hit.LLMNRName = name
			}
			hits[ip] = hit
		}
	}

	go readPacketsUntil(ctx, conn, deadline, func(_ net.Addr, data []byte) {
		mergePacket(data)
	})
	waitUntil(ctx, deadline)
	return hits
}

func discoverLLMNRFromPacket(data []byte) map[string]discoveryHit {
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
		if name == "" {
			continue
		}
		hit := hits[ip]
		hit.IP = ip
		hit.Sources = appendSource(hit.Sources, "llmnr")
		hit.LLMNRName = name
		hits[ip] = hit
	}
	return hits
}
