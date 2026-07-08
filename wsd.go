package main

import (
	"context"
	"encoding/xml"
	"net"
	"strings"
	"sync"
	"time"
)

const wsdProbeMessage = `<?xml version="1.0" encoding="utf-8"?>` +
	`<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" ` +
	`xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" ` +
	`xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">` +
	`<soap:Header>` +
	`<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>` +
	`<wsa:MessageID>urn:uuid:ipscry-probe</wsa:MessageID>` +
	`<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>` +
	`</soap:Header><soap:Body><wsd:Probe/></soap:Body></soap:Envelope>`

func discoverWSD(ctx context.Context, iface *net.Interface, deadline time.Time) map[string]discoveryHit {
	hits := map[string]discoveryHit{}
	group := net.IPv4(239, 255, 255, 250)
	conn, err := listenMulticastUDP(iface, group, 3702)
	if err != nil {
		return hits
	}
	defer conn.Close()

	var mu sync.Mutex
	go readPacketsUntil(ctx, conn, deadline, func(addr net.Addr, data []byte) {
		types, xaddrs, scopes := parseWSDResponse(data)
		ip := hostAddrIP(addr)
		if ip == "" {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		hit := hits[ip]
		hit.IP = ip
		hit.Sources = appendSource(hit.Sources, "wsd")
		hit.WSDTypes = appendUniqueStrings(hit.WSDTypes, types...)
		hit.WSDXAddrs = appendUniqueStrings(hit.WSDXAddrs, xaddrs...)
		hit.WSDScopes = appendUniqueStrings(hit.WSDScopes, scopes...)
		hits[ip] = hit
	})

	_ = sendMulticastUDP(iface, group, 3702, []byte(wsdProbeMessage))
	waitUntil(ctx, deadline)
	return hits
}

type wsdEnvelope struct {
	Body wsdBody `xml:"Body"`
}

type wsdBody struct {
	ProbeMatches wsdProbeMatches `xml:"ProbeMatches"`
}

type wsdProbeMatches struct {
	Matches []wsdProbeMatch `xml:"ProbeMatch"`
}

type wsdProbeMatch struct {
	Types  string `xml:"Types"`
	XAddrs string `xml:"XAddrs"`
	Scopes string `xml:"Scopes"`
}

func parseWSDResponse(data []byte) (types, xaddrs, scopes []string) {
	text := string(data)
	if !strings.Contains(text, "ProbeMatches") && !strings.Contains(text, "ProbeMatch") {
		return nil, nil, nil
	}
	var env wsdEnvelope
	if err := xml.Unmarshal(data, &env); err == nil {
		for _, match := range env.Body.ProbeMatches.Matches {
			types = appendUniqueStrings(types, splitWSDField(match.Types)...)
			xaddrs = appendUniqueStrings(xaddrs, splitWSDField(match.XAddrs)...)
			scopes = appendUniqueStrings(scopes, splitWSDField(match.Scopes)...)
		}
	}
	if len(types) == 0 {
		types = splitWSDField(extractXMLTag(text, "wsd:Types"))
		if len(types) == 0 {
			types = splitWSDField(extractXMLTag(text, "Types"))
		}
	}
	if len(xaddrs) == 0 {
		xaddrs = splitWSDField(extractXMLTag(text, "wsd:XAddrs"))
		if len(xaddrs) == 0 {
			xaddrs = splitWSDField(extractXMLTag(text, "XAddrs"))
		}
	}
	if len(scopes) == 0 {
		scopes = splitWSDField(extractXMLTag(text, "wsd:Scopes"))
		if len(scopes) == 0 {
			scopes = splitWSDField(extractXMLTag(text, "Scopes"))
		}
	}
	return types, xaddrs, scopes
}

func splitWSDField(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	raw = strings.ReplaceAll(raw, "\n", " ")
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\r'
	})
	var out []string
	for _, part := range parts {
		part = sanitizeOneLine(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
