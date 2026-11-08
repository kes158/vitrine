package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"sgwg/internal/testpeer"
)

func mustAddrPort(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

const testUser, testPass = "u-0f3c9a", "p-7d21be"

type harness struct {
	peer   *testpeer.Peer
	engine *Engine
}

func startTunnel(t *testing.T, mutate func(string) string) *harness {
	t.Helper()
	peer, err := testpeer.Start(testpeer.Options{Keepalive: 0})
	if err != nil {
		t.Fatalf("test peer: %v", err)
	}
	t.Cleanup(peer.Close)
	text := peer.ClientConfig
	if mutate != nil {
		text = mutate(text)
	}
	p, err := ParseProfile(text)
	if err != nil {
		t.Fatalf("client profile rejected: %v", err)
	}
	e, err := StartEngine(p, testUser, testPass, EngineOptions{DialTimeout: 4 * time.Second})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	t.Cleanup(e.Close)
	return &harness{peer, e}
}

func (h *harness) socksClient(t *testing.T, user, pass string) *http.Client {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(h.engine.Port())),
		&proxy.Auth{User: user, Password: pass}, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			// The SOCKS dialer sends the hostname (ATYP=3); this process never
			// resolves fixture.test, which only the tunnel's DNS knows.
			DialContext:       dialer.(proxy.ContextDialer).DialContext,
			TLSClientConfig:   &tls.Config{RootCAs: h.peer.CertPool(), ServerName: "fixture.test"},
			DisableKeepAlives: true,
		},
	}
}

func (h *harness) connectClient(user, pass string) *http.Client {
	u := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", fmt.Sprint(h.engine.Port()))}
	if user != "" {
		u.User = url.UserPassword(user, pass)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(u),
			TLSClientConfig:   &tls.Config{RootCAs: h.peer.CertPool(), ServerName: "fixture.test"},
			DisableKeepAlives: true,
		},
	}
}

func get(t *testing.T, c *http.Client, target, rangeHeader string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest("GET", target, nil)
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp.Header
}

func TestTunnelHandshakeDNSHTTPSAndRange(t *testing.T) {
	h := startTunnel(t, nil)
	client := h.socksClient(t, testUser, testPass)

	status, body, _ := get(t, client, "http://fixture.test/", "")
	if status != 200 || body != "through-tunnel" {
		t.Fatalf("HTTP through tunnel: %d %q", status, body)
	}
	if h.peer.DNSQueries.Load() == 0 {
		t.Fatal("hostname was not resolved by the tunnel DNS server")
	}
	status, body, _ = get(t, client, "https://fixture.test/", "")
	if status != 200 || body != "through-tunnel" || h.peer.HTTPSHits.Load() == 0 {
		t.Fatalf("HTTPS through tunnel: %d %q", status, body)
	}
	status, body, header := get(t, client, "https://media.fixture.test/media", "bytes=5-13")
	want := string(testpeer.MediaBody[5:14])
	if status != 206 || body != want || header.Get("Content-Range") != fmt.Sprintf("bytes 5-13/%d", len(testpeer.MediaBody)) {
		t.Fatalf("range request: %d %q %q", status, body, header.Get("Content-Range"))
	}
	status, body, _ = get(t, client, "https://fixture.test/cdn-cgi/trace", "")
	if status != 200 || !strings.Contains(body, "ip="+testpeer.ClientAddr.String()) {
		t.Fatalf("trace must report the tunnel address as the source: %q", body)
	}

	st := h.engine.Status()
	if age := st["handshakeAgeSec"].(int64); age < 0 || age > 30 {
		t.Fatalf("no recent WireGuard handshake: %v", st)
	}
	if st["wgRxBytes"].(int64) == 0 || st["wgTxBytes"].(int64) == 0 {
		t.Fatalf("no encrypted traffic counted: %v", st)
	}
	conns := st["connections"].(map[string]int64)
	if conns["domainTargets"] < 4 || conns["ipTargets"] != 0 || conns["failed"] != 0 || conns["socks"] < 4 {
		t.Fatalf("unexpected connection counters: %v", conns)
	}
	b, _ := json.Marshal(st)
	for _, leak := range []string{"fixture.test", "127.0.0.1", "private", "10.66.0.1"} {
		if strings.Contains(string(b), leak) {
			t.Fatalf("status leaks %q: %s", leak, b)
		}
	}
}

func TestHTTPConnectForFFmpegStyleClients(t *testing.T) {
	h := startTunnel(t, nil)
	// Without credentials the proxy must answer 407 and never reach the origin.
	before := h.peer.HTTPSHits.Load()
	_, err := h.connectClient("", "").Get("https://fixture.test/")
	if err == nil || h.peer.HTTPSHits.Load() != before {
		t.Fatalf("unauthenticated CONNECT reached the origin: %v", err)
	}
	status, body, _ := get(t, h.connectClient(testUser, testPass), "https://fixture.test/media", "bytes=0-3")
	if status != 206 || body != string(testpeer.MediaBody[:4]) {
		t.Fatalf("authenticated CONNECT range: %d %q", status, body)
	}

	// FFmpeg's tls+httpproxy first sends CONNECT without credentials, expects a
	// 407 Basic challenge, then reconnects with Proxy-Authorization.
	addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(h.engine.Port()))
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "CONNECT fixture.test:443 HTTP/1.1\r\nHost: fixture.test:443\r\nConnection: close\r\n\r\n")
	reply, _ := io.ReadAll(c)
	c.Close()
	if !strings.HasPrefix(string(reply), "HTTP/1.1 407") || !strings.Contains(string(reply), `Proxy-Authenticate: Basic realm="ytmu"`) {
		t.Fatalf("challenge: %q", reply)
	}
	if h.engine.Status()["connections"].(map[string]int64)["httpConnect"] != 1 {
		t.Fatal("CONNECT counter")
	}
}

func TestNoDirectFallback(t *testing.T) {
	// A server reachable directly from this host, but not through the tunnel.
	direct, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	var directHits atomic.Int64
	go http.Serve(direct, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { directHits.Add(1) }))

	h := startTunnel(t, nil)
	client := h.socksClient(t, testUser, testPass)
	client.Timeout = 8 * time.Second
	if _, err := client.Get("http://" + direct.Addr().String() + "/"); err == nil {
		t.Fatal("request outside the tunnel succeeded")
	}
	// A name the tunnel DNS does not know must fail, not be resolved locally.
	if _, err := client.Get("http://localhost:" + fmt.Sprint(direct.Addr().(*net.TCPAddr).Port) + "/"); err == nil {
		t.Fatal("unknown name succeeded")
	}
	if directHits.Load() != 0 {
		t.Fatal("traffic bypassed the tunnel")
	}
	conns := h.engine.Status()["connections"].(map[string]int64)
	if conns["failed"] < 2 || conns["dnsFailed"] < 1 {
		t.Fatalf("failures not counted: %v", conns)
	}

	// With the WireGuard peer gone, requests fail instead of going direct.
	h.peer.Close()
	if _, err := client.Get("http://fixture.test/"); err == nil {
		t.Fatal("request succeeded without a WireGuard peer")
	}
}

func TestUnreachableEndpointFailsClosed(t *testing.T) {
	h := startTunnel(t, func(text string) string {
		// Point the profile at a UDP port nobody listens on.
		pc, _ := net.ListenPacket("udp4", "127.0.0.1:0")
		port := pc.LocalAddr().(*net.UDPAddr).Port
		pc.Close()
		lines := strings.Split(text, "\n")
		for i, l := range lines {
			if strings.HasPrefix(l, "Endpoint = ") {
				lines[i] = fmt.Sprintf("Endpoint = 127.0.0.1:%d", port)
			}
		}
		return strings.Join(lines, "\n")
	})
	client := h.socksClient(t, testUser, testPass)
	client.Timeout = 8 * time.Second
	if _, err := client.Get("http://fixture.test/"); err == nil {
		t.Fatal("request succeeded without a handshake")
	}
	if h.engine.Status()["handshakeAgeSec"].(int64) != -1 {
		t.Fatal("handshake reported without a peer")
	}
}

func TestRebindAndListenerRecovery(t *testing.T) {
	h := startTunnel(t, nil)
	client := h.socksClient(t, testUser, testPass)
	if status, _, _ := get(t, client, "http://fixture.test/", ""); status != 200 {
		t.Fatal("initial request")
	}
	if err := h.engine.Rebind(); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	if status, _, _ := get(t, client, "http://fixture.test/", ""); status != 200 {
		t.Fatal("request after UDP rebind")
	}
	// Simulate iOS defuncting the listening socket while suspended.
	port := h.engine.Port()
	h.engine.mu.Lock()
	h.engine.listener.Close()
	h.engine.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for h.engine.relistens.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if h.engine.Port() != port || h.engine.relistens.Load() != 1 {
		t.Fatalf("listener not recovered on the same port: %d", h.engine.relistens.Load())
	}
	if status, _, _ := get(t, client, "http://fixture.test/", ""); status != 200 {
		t.Fatal("request after listener recovery")
	}
	n, _, err := h.engine.Lookup("media.fixture.test", 3*time.Second)
	if err != nil || n != 1 {
		t.Fatalf("tunnel lookup: %d %v", n, err)
	}
}

func TestHostnameEndpointUsesResolverOnce(t *testing.T) {
	peer, err := testpeer.Start(testpeer.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	text := strings.Replace(peer.ClientConfig, "Endpoint = 127.0.0.1:", "Endpoint = wg-endpoint.example:", 1)
	p, err := ParseProfile(text)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	e, err := StartEngine(p, testUser, testPass, EngineOptions{Resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
		calls++
		if host != "wg-endpoint.example" {
			t.Errorf("unexpected lookup %q", host)
		}
		return []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	h := &harness{peer, e}
	if status, _, _ := get(t, h.socksClient(t, testUser, testPass), "http://fixture.test/", ""); status != 200 || calls != 1 {
		t.Fatalf("hostname endpoint: status %d calls %d", status, calls)
	}
	if e.Status()["endpointResolvedLocally"] != true {
		t.Fatal("local endpoint resolution must be reported")
	}
}

func TestCategoryCounters(t *testing.T) {
	e := &Engine{}
	for _, h := range []string{"audio-fa.scdn.co", "audio-ak-spotify-com.akamaized.net", "apresolve.spotify.com",
		"spclient.wg.spotify.com", "api.spotify.com", "example.com", "audio-fa.scdn.co.evil.example"} {
		e.classify(h)
	}
	if e.media.Load() != 2 || e.api.Load() != 3 || e.other.Load() != 2 {
		t.Fatalf("media=%d api=%d other=%d", e.media.Load(), e.api.Load(), e.other.Load())
	}
}
