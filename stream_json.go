package main

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"time"
)

type streamJSONMonitor struct {
	out    io.Writer
	target string
	mu     sync.Mutex
}

func newStreamJSONMonitor(out io.Writer, target string) *streamJSONMonitor {
	return &streamJSONMonitor{out: out, target: target}
}

func (m *streamJSONMonitor) emit(event string, fields map[string]any) {
	fields["event"] = event
	fields["timestamp"] = time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = json.NewEncoder(m.out).Encode(fields)
}

func (m *streamJSONMonitor) Start(target string, totalPorts int64, enrich enrichConfig) {
	m.emit("scan_started", map[string]any{"subnet": target, "total_ports": totalPorts})
}

func (m *streamJSONMonitor) PortProgress(scanned, total int64) {
	m.emit("scan_progress", map[string]any{
		"phase": "scanning", "scanned_ports": scanned, "total_ports": total,
		"percent": progressPercent(scanned, total),
	})
}

func (m *streamJSONMonitor) PortOpen(ip string, latencyMS int64) {}

func (m *streamJSONMonitor) PortFound(result portScanResult) {
	fields := streamPortFields(result.ip, result.port)
	fields["latency_ms"] = result.latencyMS
	m.emit("target_found", fields)
}

func (m *streamJSONMonitor) EnrichStart(ips []string, enrich enrichConfig) {
	m.emit("scan_progress", map[string]any{
		"phase": "enriching", "ready_hosts": 0, "total_hosts": len(ips),
	})
}

func (m *streamJSONMonitor) HostReady(host hostResult) {
	if len(host.OpenPorts) == 0 {
		m.emit("target_updated", streamHostFields(host))
		return
	}
	for _, port := range host.OpenPorts {
		fields := streamHostFields(host)
		for key, value := range streamPortFields(host.IP, port) {
			fields[key] = value
		}
		m.emit("target_updated", fields)
	}
}

func (m *streamJSONMonitor) HTTPRefresh(updated hostResult) { m.HostReady(updated) }

func (m *streamJSONMonitor) Finish(
	hosts []hostResult, elapsed time.Duration, ctx context.Context, watch tuiWatchConfig,
) {
	event := "scan_completed"
	fields := map[string]any{
		"subnet": m.target, "host_count": len(hosts), "elapsed_ms": elapsed.Milliseconds(),
	}
	if ctx != nil && ctx.Err() != nil {
		event = "scan_failed"
		fields["error"] = ctx.Err().Error()
	}
	m.emit(event, fields)
}

func (m *streamJSONMonitor) Close() {}

func streamProtocol(port portResult) string {
	service := strings.ToLower(port.Service)
	switch {
	case strings.Contains(service, "https") || port.Port == 443 || port.Port == 8443:
		return "https"
	case strings.Contains(service, "http") || port.Port == 80 || port.Port == 631 || port.Port == 8080:
		return "http"
	default:
		return "tcp"
	}
}

func streamPortFields(ip string, port portResult) map[string]any {
	return map[string]any{
		"ip": ip, "port": port.Port, "protocol": streamProtocol(port),
		"service_hint": port.Service, "http_status": port.HTTPStatus,
		"http_server": port.HTTPServer, "title": port.HTTPTitle,
		"redirect": port.HTTPRedirect, "tls_subject": port.TLSSubject,
	}
}

func streamHostFields(host hostResult) map[string]any {
	hostnames := make([]string, 0, 3)
	for _, value := range []string{host.Hostname, host.MDNSName, host.LLMNRName} {
		if value != "" {
			hostnames = append(hostnames, value)
		}
	}
	return map[string]any{
		"ip": host.IP, "mac": host.MAC, "vendor": host.MACVendor,
		"hostname": host.Hostname, "hostnames": hostnames,
		"confidence": 0.8, "service_hint": host.Guess,
	}
}
