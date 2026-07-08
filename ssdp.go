package main

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var ssdpSearchTargets = []string{
	"ssdp:all",
	"upnp:rootdevice",
	"urn:schemas-upnp-org:device:MediaRenderer:1",
	"urn:schemas-upnp-org:device:MediaServer:1",
}

func buildSSDPMSearch(searchTarget string) []byte {
	var b strings.Builder
	b.WriteString("M-SEARCH * HTTP/1.1\r\n")
	b.WriteString("HOST: 239.255.255.250:1900\r\n")
	b.WriteString("MAN: \"ssdp:discover\"\r\n")
	b.WriteString("MX: 2\r\n")
	b.WriteString("ST: ")
	b.WriteString(searchTarget)
	b.WriteString("\r\n\r\n")
	return []byte(b.String())
}

func parseSSDPResponse(data []byte) (server, st, location, usn string) {
	text := string(data)
	if !strings.HasPrefix(text, "HTTP/1.") {
		return "", "", "", ""
	}
	for _, line := range strings.Split(text, "\r\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToUpper(strings.TrimSpace(key))
		val = sanitizeOneLine(strings.TrimSpace(val))
		switch key {
		case "SERVER":
			if server == "" {
				server = val
			}
		case "ST":
			if st == "" {
				st = val
			}
		case "LOCATION":
			if location == "" {
				location = val
			}
		case "USN":
			if usn == "" {
				usn = val
			}
		}
	}
	return server, st, location, usn
}

func discoverSSDP(ctx context.Context, iface *net.Interface, deadline time.Time) map[string]discoveryHit {
	hits := map[string]discoveryHit{}
	group := net.IPv4(239, 255, 255, 250)
	conn, err := listenMulticastUDP(iface, group, 1900)
	if err != nil {
		return hits
	}
	defer conn.Close()

	var mu sync.Mutex
	go readPacketsUntil(ctx, conn, deadline, func(addr net.Addr, data []byte) {
		server, st, location, usn := parseSSDPResponse(data)
		ip := hostAddrIP(addr)
		if ip == "" {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		hit := hits[ip]
		hit.IP = ip
		hit.Sources = appendSource(hit.Sources, "ssdp")
		if hit.SSDPServer == "" {
			hit.SSDPServer = server
		}
		if hit.UPnPType == "" {
			hit.UPnPType = firstNonEmpty(st, usn)
		}
		if hit.UPnPLocation == "" {
			hit.UPnPLocation = location
		}
		hits[ip] = hit
	})

	for _, st := range ssdpSearchTargets {
		if ctx.Err() != nil {
			break
		}
		_ = sendMulticastUDP(iface, group, 1900, buildSSDPMSearch(st))
		time.Sleep(50 * time.Millisecond)
	}
	waitUntil(ctx, deadline)
	return hits
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func fetchUPnPDescriptions(ctx context.Context, hits map[string]discoveryHit, timeout time.Duration) {
	if len(hits) == 0 {
		return
	}
	client := &http.Client{Timeout: timeout}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for ip, hit := range hits {
		if hit.UPnPLocation == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip, location string) {
			defer wg.Done()
			defer func() { <-sem }()
			friendly, model := fetchUPnPDescription(ctx, client, location)
			if friendly == "" && model == "" {
				return
			}
			cur := hits[ip]
			if cur.UPnPFriendly == "" {
				cur.UPnPFriendly = friendly
			}
			if cur.UPnPModel == "" {
				cur.UPnPModel = model
			}
			hits[ip] = cur
		}(ip, hit.UPnPLocation)
	}
	wg.Wait()
}

func fetchUPnPDescription(ctx context.Context, client *http.Client, location string) (friendly, model string) {
	if client == nil || strings.TrimSpace(location) == "" {
		return "", ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return "", ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", ""
	}
	body := make([]byte, 65536)
	n, _ := ioReadLimit(resp.Body, body)
	return parseUPnPDescription(body[:n])
}

func ioReadLimit(r interface {
	Read([]byte) (int, error)
}, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			break
		}
	}
	return total, nil
}

func parseUPnPDescription(body []byte) (friendly, model string) {
	text := string(body)
	friendly = extractXMLTag(text, "friendlyName")
	model = extractXMLTag(text, "modelName")
	if friendly == "" {
		friendly = extractXMLTag(text, "manufacturer")
	}
	return sanitizeOneLine(friendly), sanitizeOneLine(model)
}

func extractXMLTag(body, tag string) string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	start := strings.Index(strings.ToLower(body), strings.ToLower(open))
	if start < 0 {
		return ""
	}
	start += len(open)
	end := strings.Index(strings.ToLower(body[start:]), strings.ToLower(close))
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(body[start : start+end])
}
