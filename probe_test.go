package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func listenerPort(t *testing.T, ln net.Listener) int {
	t.Helper()
	return ln.Addr().(*net.TCPAddr).Port
}

// withCatalogEntry registers info for port for the duration of the test.
func withCatalogEntry(t *testing.T, port int, info portInfo) {
	t.Helper()
	prev, had := portCatalog[port]
	portCatalog[port] = info
	t.Cleanup(func() {
		if had {
			portCatalog[port] = prev
		} else {
			delete(portCatalog, port)
		}
	})
}

func TestPortProbeInfo(t *testing.T) {
	cases := []struct {
		port      int
		http, tls bool
	}{
		{80, true, false},    // catalog
		{8081, true, false},  // ports.csv "HTTP (alternate)"
		{3000, true, false},  // ports.csv "HTTP (dev)"
		{9443, true, true},   // ports.csv "HTTPS (alternate)"
		{10000, true, true},  // ports.csv "HTTPS"
		{6443, true, true},   // catalog: Kubernetes API
		{5986, false, true},  // catalog wins over the csv "(HTTPS)" label
		{22, false, false},   // ssh
		{9100, false, false}, // raw printer port: never send it HTTP
		{54321, false, false},
	}
	for _, c := range cases {
		got := portProbeInfo(c.port)
		if got.http != c.http || got.tls != c.tls {
			t.Errorf("portProbeInfo(%d) http=%v tls=%v, want http=%v tls=%v", c.port, got.http, got.tls, c.http, c.tls)
		}
	}
}

func TestProbeHTTPFallsBackToPlainOnTLSPort(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<title>Plain On TLS Port</title>"))
	}))
	defer server.Close()
	port := listenerPort(t, server.Listener)
	withCatalogEntry(t, port, portInfo{service: "test-https", http: true, tls: true})

	pr := portResult{Port: port}
	if !probeHTTP(context.Background(), "127.0.0.1", port, time.Second, &pr) {
		t.Fatalf("expected fallback to plain HTTP: %s", pr.ProbeError)
	}
	if pr.HTTPStatus != "200 OK" || pr.HTTPTitle != "Plain On TLS Port" {
		t.Fatalf("status=%q title=%q", pr.HTTPStatus, pr.HTTPTitle)
	}
}

func TestProbeHTTPUpgradesHTTPSOnly400(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<title>Secure Console</title>"))
	}))
	defer server.Close()
	port := listenerPort(t, server.Listener)
	withCatalogEntry(t, port, portInfo{service: "test-http", http: true})

	pr := portResult{Port: port}
	if !probeHTTP(context.Background(), "127.0.0.1", port, time.Second, &pr) {
		t.Fatalf("expected probe to succeed: %s", pr.ProbeError)
	}
	if pr.HTTPStatus != "200 OK" || pr.HTTPTitle != "Secure Console" || pr.TLSSubject == "" {
		t.Fatalf("status=%q title=%q tls=%q, want the HTTPS page", pr.HTTPStatus, pr.HTTPTitle, pr.TLSSubject)
	}
}

func TestSniffHTTPPlain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<title>Vendor Console</title>"))
	}))
	defer server.Close()
	port := listenerPort(t, server.Listener)

	pr := portResult{Port: port, Service: "unknown"}
	if !sniffHTTP(context.Background(), "127.0.0.1", port, time.Second, &pr) {
		t.Fatalf("expected HTTP to be detected: %s", pr.ProbeError)
	}
	if pr.Service != "http" || pr.HTTPTitle != "Vendor Console" {
		t.Fatalf("service=%q title=%q", pr.Service, pr.HTTPTitle)
	}
}

// A Go HTTPS server answers plaintext with a 400 "HTTPS" page; the sniff must
// end up with the real page over TLS.
func TestSniffHTTPSViaGoServer(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<title>TLS Console</title>"))
	}))
	defer server.Close()
	port := listenerPort(t, server.Listener)

	pr := portResult{Port: port, Service: "unknown"}
	if !sniffHTTP(context.Background(), "127.0.0.1", port, time.Second, &pr) {
		t.Fatalf("expected HTTPS to be detected: %s", pr.ProbeError)
	}
	if pr.Service != "https" || pr.HTTPTitle != "TLS Console" || pr.TLSSubject == "" {
		t.Fatalf("service=%q title=%q tls=%q", pr.Service, pr.HTTPTitle, pr.TLSSubject)
	}
}

// A bare TLS server that drops plaintext without replying (the common non-Go
// behaviour) must still be tried as HTTPS.
func TestSniffHTTPSViaSilentTLS(t *testing.T) {
	ref := httptest.NewUnstartedServer(http.NotFoundHandler())
	ref.StartTLS()
	cfg := ref.TLS.Clone()
	ref.Close()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if err := c.(*tls.Conn).Handshake(); err != nil {
					return // plaintext: drop silently
				}
				if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
					return
				}
				body := "<title>Raw TLS</title>"
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: 22\r\n\r\n" + body))
			}(c)
		}
	}()
	port := listenerPort(t, ln)

	pr := portResult{Port: port, Service: "unknown"}
	if !sniffHTTP(context.Background(), "127.0.0.1", port, time.Second, &pr) {
		t.Fatalf("expected HTTPS to be detected: %s", pr.ProbeError)
	}
	if pr.Service != "https" || pr.HTTPTitle != "Raw TLS" {
		t.Fatalf("service=%q title=%q", pr.Service, pr.HTTPTitle)
	}
}

func rawServer(t *testing.T, handle func(net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				handle(c)
			}(c)
		}
	}()
	return listenerPort(t, ln)
}

func TestSniffHTTPRecordsBannerAndSendsNothing(t *testing.T) {
	got := make(chan int, 1)
	port := rawServer(t, func(c net.Conn) {
		_, _ = c.Write([]byte("SSH-2.0-TestServer\r\n"))
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		got <- n
	})

	pr := portResult{Port: port, Service: "unknown"}
	if sniffHTTP(context.Background(), "127.0.0.1", port, time.Second, &pr) {
		t.Fatal("banner service must not be reported as HTTP")
	}
	if pr.Banner != "SSH-2.0-TestServer" {
		t.Fatalf("banner=%q", pr.Banner)
	}
	if n := <-got; n != 0 {
		t.Fatalf("sniff sent %d bytes to a banner service, want 0", n)
	}
}

func TestSniffHTTPIgnoresNonHTTPReply(t *testing.T) {
	port := rawServer(t, func(c net.Conn) {
		buf := make([]byte, 256)
		if n, _ := c.Read(buf); n > 0 {
			_, _ = c.Write([]byte("-ERR unknown command 'GET'\r\n"))
		}
	})

	pr := portResult{Port: port, Service: "unknown"}
	if sniffHTTP(context.Background(), "127.0.0.1", port, time.Second, &pr) {
		t.Fatal("non-HTTP reply must not be reported as HTTP")
	}
	if pr.HTTPStatus != "" || pr.Service != "unknown" {
		t.Fatalf("status=%q service=%q", pr.HTTPStatus, pr.Service)
	}
}

func TestPortNeedsHTTPSniff(t *testing.T) {
	cases := []struct {
		name string
		pr   portResult
		want bool
	}{
		{"unknown silent port", portResult{Port: 54321}, true},
		{"unknown port with banner", portResult{Port: 54321, Banner: "SSH-2.0"}, false},
		{"unknown port already http", portResult{Port: 54321, HTTPStatus: "200 OK"}, false},
		{"known non-web port", portResult{Port: 9100}, false},
		{"known web port", portResult{Port: 8081}, false}, // handled by portNeedsHTTPProbe
	}
	for _, c := range cases {
		if got := portNeedsHTTPSniff(c.pr); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestForEachScanJobInterleavesHosts(t *testing.T) {
	var got []string
	forEachScanJob([]string{"a", "b", "c"}, []int{1, 2}, func(ip string, port int) {
		got = append(got, ip+":"+strconv.Itoa(port))
	})
	want := []string{"a:1", "b:1", "c:1", "a:2", "b:2", "c:2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("order=%v, want %v", got, want)
	}
}

func TestHostLimiterCapsPerHostOnly(t *testing.T) {
	const limit = 3
	h := newHostLimiter(limit)
	var mu sync.Mutex
	inFlight := map[string]int{}
	peak := map[string]int{}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		ip := "a"
		if i%2 == 1 {
			ip = "b"
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			release := h.acquire(ip)
			mu.Lock()
			inFlight[ip]++
			if inFlight[ip] > peak[ip] {
				peak[ip] = inFlight[ip]
			}
			mu.Unlock()
			time.Sleep(5 * time.Millisecond)
			mu.Lock()
			inFlight[ip]--
			mu.Unlock()
			release()
		}(ip)
	}
	wg.Wait()
	for _, ip := range []string{"a", "b"} {
		if peak[ip] > limit {
			t.Fatalf("host %s peaked at %d in flight, limit %d", ip, peak[ip], limit)
		}
		if peak[ip] < 2 {
			t.Fatalf("host %s peaked at %d; limiter should still allow parallel checks", ip, peak[ip])
		}
	}
}

// End to end: an unlisted port found open by the TCP scan gets HTTP metadata
// from the second pass.
func TestRunDeepHTTPProbeSniffsUnknownPort(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<title>Unlisted</title>"))
	}))
	defer server.Close()
	port := listenerPort(t, server.Listener)
	if portIsKnown(port) {
		t.Skipf("ephemeral port %d collides with a known port", port)
	}

	res, ok := scanPort(context.Background(), "127.0.0.1", port, time.Second)
	if !ok {
		t.Fatal("expected port open")
	}
	if res.port.HTTPStatus != "" {
		t.Fatalf("first pass should not probe unknown ports, got %q", res.port.HTTPStatus)
	}
	hosts := []hostResult{{IP: "127.0.0.1", OpenPorts: []portResult{res.port}}}
	runDeepHTTPProbe(context.Background(), hosts, 2*time.Second, httpProbeConcurrency, nil, nil)

	got := hosts[0].OpenPorts[0]
	if got.HTTPStatus != "200 OK" || got.HTTPTitle != "Unlisted" || got.Service != "http" {
		t.Fatalf("status=%q title=%q service=%q", got.HTTPStatus, got.HTTPTitle, got.Service)
	}
}
